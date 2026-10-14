"""Chroma ingestion and retrieval helpers for known Solidity vulnerabilities."""

import argparse
import hashlib
import json
import os
import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from dotenv import load_dotenv
from langchain.docstore.document import Document

from utils.print_utils import create_progress_bar, print_step

load_dotenv()

# V2 keeps ordinary Solidity functions intact whenever they fit.  These values
# are deliberately expressed in an inexpensive lexical-token estimate so the
# ingestion process is fully local and does not need to download a tokenizer.
V2_CHUNK_TARGET_TOKENS = 800
V2_CHUNK_MAX_TOKENS = 900
V2_CHUNK_OVERLAP_TOKENS = 100
V2_DATASET = "known_vulnerabilities"
V2_DOCUMENT_TYPE = "vulnerable_contract"
_LINE_MARKER = re.compile(r"^<LINE=(\d+)>(.*)$")
_SOLIDITY_MEMBER_START = re.compile(
    r"^(?:function\s+|modifier\s+|constructor\s*\(|fallback\s*\(|receive\s*\()"
)
_CONTRACT_NAME = re.compile(r"\b(?:abstract\s+)?(?:contract|library|interface)\s+([A-Za-z_]\w*)")
_LEXICAL_TOKEN = re.compile(r"\w+|[^\s\w]", re.UNICODE)


def load_json_vulns(json_path: str) -> list:
    """Load the contract-vulnerability manifest."""
    with open(json_path, "r", encoding="utf-8") as file:
        return json.load(file)


def _label_source_lines(full_text: str) -> List[str]:
    return [f"<LINE={number}>{line}" for number, line in enumerate(full_text.split("\n"), start=1)]


def _line_number(labeled_line: str) -> int:
    match = _LINE_MARKER.match(labeled_line)
    if not match:
        raise ValueError(f"Malformed source line marker: {labeled_line!r}")
    return int(match.group(1))


def _source_line(labeled_line: str) -> str:
    match = _LINE_MARKER.match(labeled_line)
    return match.group(2) if match else labeled_line


def _estimated_tokens(lines: Iterable[str]) -> int:
    """Estimate code tokens locally; accurate enough to enforce the v2 range."""
    return sum(len(_LEXICAL_TOKEN.findall(_source_line(line))) for line in lines)


def _solidity_sections(labeled_lines: Sequence[str]) -> List[List[str]]:
    """Split only at top-level contract members, retaining complete functions."""
    if not labeled_lines:
        return []

    starts = [0]
    depth = 0
    for index, labeled_line in enumerate(labeled_lines):
        source_line = _source_line(labeled_line)
        # A member begins at contract-body depth one.  This intentionally
        # leaves state declarations and the contract declaration together.
        if index and depth == 1 and _SOLIDITY_MEMBER_START.match(source_line.strip()):
            starts.append(index)
        depth += source_line.count("{") - source_line.count("}")

    starts.append(len(labeled_lines))
    return [list(labeled_lines[start:end]) for start, end in zip(starts, starts[1:]) if start < end]


def _tail_within_budget(lines: Sequence[str], token_budget: int) -> List[str]:
    tail: List[str] = []
    for line in reversed(lines):
        candidate = [line, *tail]
        if _estimated_tokens(candidate) > token_budget:
            break
        tail = candidate
    return tail


def _split_oversized_section(section: Sequence[str]) -> List[List[str]]:
    """Split only an oversized Solidity member, retaining 100-token context."""
    chunks: List[List[str]] = []
    current: List[str] = []
    for line in section:
        if current and _estimated_tokens([*current, line]) > V2_CHUNK_TARGET_TOKENS:
            chunks.append(current)
            current = _tail_within_budget(current, V2_CHUNK_OVERLAP_TOKENS)
        current.append(line)
    if current:
        chunks.append(current)
    return chunks


def _solidity_oriented_chunks(full_text: str) -> List[List[str]]:
    """Create 800-token Solidity-aware chunks with approximately 12.5% overlap."""
    sections = _solidity_sections(_label_source_lines(full_text))
    chunks: List[List[str]] = []
    current: List[str] = []

    for section in sections:
        section_tokens = _estimated_tokens(section)
        if section_tokens > V2_CHUNK_MAX_TOKENS:
            if current:
                chunks.append(current)
                current = []
            chunks.extend(_split_oversized_section(section))
            continue

        if not current:
            current = list(section)
            continue

        if _estimated_tokens([*current, *section]) <= V2_CHUNK_TARGET_TOKENS:
            current.extend(section)
            continue

        chunks.append(current)
        overlap_budget = min(
            V2_CHUNK_OVERLAP_TOKENS,
            max(0, V2_CHUNK_MAX_TOKENS - section_tokens),
        )
        current = [*_tail_within_budget(current, overlap_budget), *section]

    if current:
        chunks.append(current)
    return chunks


def _chunk_document(
    chunk: Sequence[str],
    line_vulns: Dict[int, List[str]],
    filename: str,
    pragma: str,
    source: str,
    dataset: str,
    document_type: str,
    contract_name: str,
) -> Document:
    line_numbers = [_line_number(line) for line in chunk]
    start_line, end_line = min(line_numbers), max(line_numbers)
    vuln_lines = [line for line in range(start_line, end_line + 1) if line in line_vulns]
    categories = sorted({category for line in vuln_lines for category in line_vulns[line]})
    return Document(
        page_content="\n".join(_source_line(line) for line in chunk),
        metadata={
            "filename": filename,
            "pragma": pragma,
            "source": source,
            "start_line": start_line,
            "end_line": end_line,
            "vuln_lines": ",".join(map(str, vuln_lines)),
            "vuln_categories": ",".join(categories),
            "dataset": dataset,
            "document_type": document_type,
            "contract_name": contract_name,
        },
    )


def chunk_contract_with_metadata(
    full_text: str,
    line_vulns: dict,
    filename: str,
    pragma: str = "",
    source: str = "",
    dataset: str = V2_DATASET,
    document_type: str = V2_DOCUMENT_TYPE,
) -> list:
    """Create Solidity-aware, line-traceable documents for one source contract."""
    contract_match = _CONTRACT_NAME.search(full_text)
    contract_name = contract_match.group(1) if contract_match else Path(filename).stem
    return [
        _chunk_document(
            chunk,
            line_vulns,
            filename,
            pragma,
            source,
            dataset,
            document_type,
            contract_name,
        )
        for chunk in _solidity_oriented_chunks(full_text)
        if chunk
    ]


def _clean_metadata(documents: Iterable[Document]) -> None:
    """Defensively ensure all metadata stays within Chroma's scalar types."""
    for document in documents:
        document.metadata = {
            key: ",".join(map(str, value))
            if isinstance(value, (list, tuple, set))
            else json.dumps(value, sort_keys=True)
            if isinstance(value, dict)
            else value
            for key, value in document.metadata.items()
        }


def build_chroma_vectorstore_from_json(
    json_path: str,
    base_dataset_dir: str,
    persist_directory: str = "./chroma_db",
):
    """Legacy active-store builder. Existing persisted stores are always reused."""
    from chromadb.config import Settings
    from langchain_chroma import Chroma
    from langchain_ollama import OllamaEmbeddings

    print_step("Initializing Local ChromaDB...")
    try:
        embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"))
        vectorstore = Chroma(
            persist_directory=persist_directory,
            embedding_function=embeddings,
            client_settings=Settings(anonymized_telemetry=False),
        )
    except Exception as error:
        print_step(f"Failed to initialize ChromaDB: {error}")
        return None

    try:
        existing = vectorstore.get()
        if existing and existing["ids"]:
            print_step(f"Loaded existing Chroma database with {len(existing['ids'])} vectors.")
            return vectorstore
    except Exception:
        pass

    vuln_data = load_json_vulns(json_path)
    all_docs: List[Document] = []
    for cdata in vuln_data:
        full_path = os.path.join(base_dataset_dir, cdata["path"])
        if not os.path.isfile(full_path):
            print(f"Warning: File not found: {full_path}")
            continue
        with open(full_path, "r", encoding="utf-8") as file:
            contract_source = file.read()
        line_vulns: Dict[int, List[str]] = {}
        for vuln in cdata.get("vulnerabilities", []):
            for line in vuln["lines"]:
                line_vulns.setdefault(line, []).append(vuln["category"])
        all_docs.extend(
            chunk_contract_with_metadata(
                contract_source,
                line_vulns,
                filename=cdata.get("name", ""),
                pragma=cdata.get("pragma", ""),
                source=cdata.get("source", ""),
            )
        )

    _clean_metadata(all_docs)
    print_step(f"Embedding {len(all_docs)} chunks...")
    try:
        vectorstore.add_documents(all_docs)
    except Exception as error:
        print_step(f"Failed to add documents to ChromaDB: {error}")
        return None
    print_step("Local ChromaDB created successfully.")
    return vectorstore


def _manifest_documents(json_path: str, base_dataset_dir: str) -> Tuple[List[Document], List[str], dict]:
    """Read and deduplicate the manifest corpus for the explicit v2 builder."""
    manifest = load_json_vulns(json_path)
    documents: List[Document] = []
    ids: List[str] = []
    categories: Counter = Counter()
    source_hashes = set()
    successfully_read = skipped = duplicate_sources = 0

    with create_progress_bar("Processing v2 contracts") as progress:
        task = progress.add_task("Processing...", total=len(manifest))
        for contract in manifest:
            relative_path = Path(contract["path"])
            full_path = Path(base_dataset_dir) / relative_path
            if not full_path.is_file():
                print(f"Warning: File not found: {full_path}")
                skipped += 1
                progress.update(task, advance=1)
                continue
            contract_source = full_path.read_text(encoding="utf-8")
            successfully_read += 1
            source_hash = hashlib.sha256(contract_source.encode("utf-8")).hexdigest()
            if source_hash in source_hashes:
                duplicate_sources += 1
                progress.update(task, advance=1)
                continue
            source_hashes.add(source_hash)

            line_vulns: Dict[int, List[str]] = {}
            for vulnerability in contract.get("vulnerabilities", []):
                for line in vulnerability["lines"]:
                    line_vulns.setdefault(line, []).append(vulnerability["category"])
            contract_docs = chunk_contract_with_metadata(
                contract_source,
                line_vulns,
                filename=contract.get("name", ""),
                pragma=contract.get("pragma", ""),
                source=contract.get("source", ""),
            )
            for index, document in enumerate(contract_docs):
                identity = "|".join(
                    (
                        relative_path.as_posix(),
                        str(index),
                        str(document.metadata["start_line"]),
                        str(document.metadata["end_line"]),
                        hashlib.sha256(document.page_content.encode("utf-8")).hexdigest(),
                    )
                )
                ids.append(hashlib.sha256(identity.encode("utf-8")).hexdigest())
            documents.extend(contract_docs)
            categories[relative_path.parts[1] if len(relative_path.parts) > 1 else "other"] += 1
            progress.update(task, advance=1)

    _clean_metadata(documents)
    return documents, ids, {
        "source_contracts": len(manifest),
        "successfully_read": successfully_read,
        "skipped": skipped,
        "duplicate_sources": duplicate_sources,
        "categories": categories,
    }


def verify_v2_vectorstore(vectorstore, expected_ids: Sequence[str]) -> dict:
    """Read-only verification of a completed v2 collection."""
    stored = vectorstore.get(include=["documents", "metadatas", "embeddings"])
    ids = stored.get("ids", [])
    metadatas = stored.get("metadatas", [])
    documents = stored.get("documents", [])
    embeddings = stored.get("embeddings", [])
    scalar_types = (str, int, float, bool)
    unsupported = [
        (index, key, type(value).__name__)
        for index, metadata in enumerate(metadatas)
        for key, value in metadata.items()
        if not isinstance(value, scalar_types)
    ]
    dimensions = {len(embedding) for embedding in embeddings if embedding is not None}
    result = {
        "vector_count": len(ids),
        "collection_exists": bool(ids),
        "metadata_exists": bool(metadatas) and all(bool(metadata) for metadata in metadatas),
        "dimensions": dimensions,
        "unsupported_metadata": unsupported,
        "duplicate_ids": len(ids) != len(set(ids)) or len(expected_ids) != len(set(expected_ids)),
        "ids_match": set(ids) == set(expected_ids),
        "samples": [
            {
                "filename": metadata.get("filename"),
                "vulnerability_category": metadata.get("vuln_categories"),
                "start_line": metadata.get("start_line"),
                "end_line": metadata.get("end_line"),
                "chunk_length": len(document),
            }
            for metadata, document in zip(metadatas[:3], documents[:3])
        ],
    }
    print_step(
        "V2 verification: "
        f"vectors={result['vector_count']}, dimensions={sorted(dimensions)}, "
        f"metadata={'ok' if result['metadata_exists'] else 'missing'}, "
        f"duplicate_ids={'yes' if result['duplicate_ids'] else 'no'}"
    )
    for sample in result["samples"]:
        print_step(
            "Sample: "
            f"{sample['filename']} cats={sample['vulnerability_category']} "
            f"lines={sample['start_line']}-{sample['end_line']} chars={sample['chunk_length']}"
        )
    return result


def rebuild_v2_knowledge_base(
    json_path: str,
    base_dataset_dir: str,
    persist_directory: str = "./chroma_db_v2",
):
    """Explicitly replace and build the isolated Phase 2 Chroma v2 database."""
    from chromadb.config import Settings
    from langchain_chroma import Chroma
    from langchain_ollama import OllamaEmbeddings

    target = Path(persist_directory).resolve()
    if target.name == "chroma_db":
        raise ValueError("Refusing to rebuild the active chroma_db; use a separate v2 directory.")
    documents, ids, summary = _manifest_documents(json_path, base_dataset_dir)
    if not documents:
        raise RuntimeError("V2 ingestion found no source documents; no database was created.")
    if len(ids) != len(set(ids)):
        raise RuntimeError("Deterministic v2 chunk identifiers are not unique.")

    # This is an explicit rebuild operation. It is the only code path that
    # removes persisted data, and it is guarded from targeting chroma_db.
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)

    embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url="http://127.0.0.1:11434")
    vectorstore = Chroma(
        collection_name="langchain",
        persist_directory=str(target),
        embedding_function=embeddings,
        client_settings=Settings(anonymized_telemetry=False),
    )
    print_step(f"Embedding {len(documents)} v2 chunks...")
    vectorstore.add_documents(documents, ids=ids)

    print_step("V2 ingestion summary:")
    print_step(f"Source contracts: {summary['source_contracts']}")
    print_step(f"Contracts successfully read: {summary['successfully_read']}")
    print_step(f"Contracts skipped: {summary['skipped']}")
    print_step(f"Duplicate source documents skipped: {summary['duplicate_sources']}")
    print_step(f"Total chunks: {len(documents)}")
    print_step(f"Total vectors: {vectorstore._collection.count()}")
    for category, count in sorted(summary["categories"].items()):
        print_step(f"{category}: {count}")
    print_step(f"Chroma database: {target}")
    print_step("Collection: langchain")
    print_step("Embedding model: nomic-embed-text")
    verification = verify_v2_vectorstore(vectorstore, ids)
    return vectorstore, {**summary, "total_chunks": len(documents), "verification": verification}


def get_vuln_retriever_from_json(
    json_path: str,
    base_dataset_dir: str,
    persist_directory: str = "./chroma_db",
    top_k: int = 5,
):
    """Return the unchanged active RAG retriever."""
    vectorstore = build_chroma_vectorstore_from_json(
        json_path=json_path,
        base_dataset_dir=base_dataset_dir,
        persist_directory=persist_directory,
    )
    if vectorstore is None:
        print_step("RAG retriever unavailable.")
        return None
    return vectorstore.as_retriever(search_kwargs={"k": top_k})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Explicit Phase 2 RAG knowledge-base operations")
    parser.add_argument("--rebuild-v2", action="store_true", help="Replace and rebuild chroma_db_v2")
    args = parser.parse_args()
    if not args.rebuild_v2:
        parser.error("Pass --rebuild-v2 to run the explicit v2 ingestion.")
    project_root = Path(__file__).resolve().parent.parent
    rebuild_v2_knowledge_base(
        json_path=str(project_root / "known_vulnerabilities" / "contract_vulns.json"),
        base_dataset_dir=str(project_root / "known_vulnerabilities"),
        persist_directory=str(project_root / "chroma_db_v2"),
    )

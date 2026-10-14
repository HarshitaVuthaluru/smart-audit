# pylint: disable=unused-import,relative-beyond-top-level
from slither.detectors.examples.backdoor import Backdoor
from slither.detectors.variables.uninitialized_state_variables import (
    UninitializedStateVarsDetection,
)
from slither.detectors.variables.uninitialized_storage_variables import (
    UninitializedStorageVars,
)
from slither.detectors.variables.uninitialized_local_variables import (
    UninitializedLocalVars,
)
from slither.detectors.variables.var_read_using_this import VarReadUsingThis
from slither.detectors.attributes.constant_pragma import ConstantPragma
from slither.detectors.attributes.incorrect_solc import IncorrectSolc
from slither.detectors.attributes.locked_ether import LockedEther
from slither.detectors.functions.arbitrary_send_eth import ArbitrarySendEth
from slither.detectors.erc.erc20.arbitrary_send_erc20_no_permit import (
    ArbitrarySendErc20NoPermit,
)
from slither.detectors.erc.erc20.arbitrary_send_erc20_permit import (
    ArbitrarySendErc20Permit,
)
from slither.detectors.functions.suicidal import Suicidal

# from .functions.complex_function import ComplexFunction
from slither.detectors.reentrancy.reentrancy_benign import ReentrancyBenign
from slither.detectors.reentrancy.reentrancy_read_before_write import (
    ReentrancyReadBeforeWritten,
)
from slither.detectors.reentrancy.reentrancy_eth import ReentrancyEth
from slither.detectors.reentrancy.reentrancy_no_gas import ReentrancyNoGas
from slither.detectors.reentrancy.reentrancy_events import ReentrancyEvent
from slither.detectors.variables.unused_state_variables import UnusedStateVars
from slither.detectors.variables.could_be_constant import CouldBeConstant
from slither.detectors.variables.could_be_immutable import CouldBeImmutable
from slither.detectors.statements.tx_origin import TxOrigin
from slither.detectors.statements.assembly import Assembly
from slither.detectors.operations.low_level_calls import LowLevelCalls
from slither.detectors.operations.unused_return_values import UnusedReturnValues
from slither.detectors.operations.unchecked_transfer import UncheckedTransfer
from slither.detectors.naming_convention.naming_convention import NamingConvention
from slither.detectors.functions.external_function import ExternalFunction
from slither.detectors.statements.controlled_delegatecall import ControlledDelegateCall
from slither.detectors.attributes.const_functions_asm import ConstantFunctionsAsm
from slither.detectors.attributes.const_functions_state import ConstantFunctionsState
from slither.detectors.shadowing.abstract import ShadowingAbstractDetection
from slither.detectors.shadowing.state import StateShadowing
from slither.detectors.shadowing.local import LocalShadowing
from slither.detectors.shadowing.builtin_symbols import BuiltinSymbolShadowing
from slither.detectors.operations.block_timestamp import Timestamp
from slither.detectors.statements.calls_in_loop import MultipleCallsInLoop
from slither.detectors.statements.incorrect_strict_equality import (
    IncorrectStrictEquality,
)
from slither.detectors.erc.erc20.incorrect_erc20_interface import (
    IncorrectERC20InterfaceDetection,
)
from slither.detectors.erc.incorrect_erc721_interface import (
    IncorrectERC721InterfaceDetection,
)
from slither.detectors.erc.unindexed_event_parameters import (
    UnindexedERC20EventParameters,
)
from slither.detectors.statements.deprecated_calls import DeprecatedStandards
from slither.detectors.source.rtlo import RightToLeftOverride
from slither.detectors.statements.too_many_digits import TooManyDigits
from slither.detectors.operations.unchecked_low_level_return_values import (
    UncheckedLowLevel,
)
from slither.detectors.operations.unchecked_send_return_value import UncheckedSend
from slither.detectors.operations.void_constructor import VoidConstructor
from slither.detectors.statements.type_based_tautology import TypeBasedTautology
from slither.detectors.statements.boolean_constant_equality import BooleanEquality
from slither.detectors.statements.boolean_constant_misuse import BooleanConstantMisuse
from slither.detectors.statements.divide_before_multiply import DivideBeforeMultiply
from slither.detectors.statements.unprotected_upgradeable import UnprotectedUpgradeable
from slither.detectors.slither.name_reused import NameReused

from slither.detectors.functions.unimplemented import UnimplementedFunctionDetection
from slither.detectors.statements.mapping_deletion import MappingDeletionDetection
from slither.detectors.statements.array_length_assignment import ArrayLengthAssignment
from slither.detectors.variables.function_init_state_variables import (
    FunctionInitializedState,
)
from slither.detectors.statements.redundant_statements import RedundantStatements
from slither.detectors.operations.bad_prng import BadPRNG
from slither.detectors.statements.costly_operations_in_loop import (
    CostlyOperationsInLoop,
)
from slither.detectors.statements.assert_state_change import AssertStateChange
from slither.detectors.attributes.unimplemented_interface import MissingInheritance
from slither.detectors.assembly.shift_parameter_mixup import ShiftParameterMixup
from slither.detectors.compiler_bugs.storage_signed_integer_array import (
    StorageSignedIntegerArray,
)
from slither.detectors.compiler_bugs.uninitialized_function_ptr_in_constructor import (
    UninitializedFunctionPtrsConstructor,
)
from slither.detectors.compiler_bugs.storage_ABIEncoderV2_array import ABIEncoderV2Array
from slither.detectors.compiler_bugs.array_by_reference import ArrayByReference
from slither.detectors.compiler_bugs.enum_conversion import EnumConversion
from slither.detectors.compiler_bugs.multiple_constructor_schemes import (
    MultipleConstructorSchemes,
)
from slither.detectors.compiler_bugs.public_mapping_nested import PublicMappingNested
from slither.detectors.compiler_bugs.reused_base_constructor import (
    ReusedBaseConstructor,
)
from slither.detectors.operations.missing_events_access_control import (
    MissingEventsAccessControl,
)
from slither.detectors.operations.missing_events_arithmetic import (
    MissingEventsArithmetic,
)
from slither.detectors.functions.modifier import ModifierDefaultDetection
from slither.detectors.variables.predeclaration_usage_local import (
    PredeclarationUsageLocal,
)
from slither.detectors.statements.unary import IncorrectUnaryExpressionDetection
from slither.detectors.operations.missing_zero_address_validation import (
    MissingZeroAddressValidation,
)
from slither.detectors.functions.dead_code import DeadCode
from slither.detectors.statements.write_after_write import WriteAfterWrite
from slither.detectors.statements.msg_value_in_loop import MsgValueInLoop
from slither.detectors.statements.delegatecall_in_loop import DelegatecallInLoop
from slither.detectors.functions.protected_variable import ProtectedVariables
from slither.detectors.functions.permit_domain_signature_collision import (
    DomainSeparatorCollision,
)
from slither.detectors.functions.codex import Codex
from slither.detectors.functions.cyclomatic_complexity import CyclomaticComplexity
from slither.detectors.operations.cache_array_length import CacheArrayLength
from slither.detectors.statements.incorrect_using_for import IncorrectUsingFor
from slither.detectors.operations.encode_packed import EncodePackedCollision
from slither.detectors.assembly.incorrect_return import IncorrectReturn
from slither.detectors.assembly.return_instead_of_leave import ReturnInsteadOfLeave
from slither.detectors.operations.incorrect_exp import IncorrectOperatorExponentiation
from slither.detectors.statements.tautological_compare import TautologicalCompare
from slither.detectors.statements.return_bomb import ReturnBomb
from slither.detectors.functions.out_of_order_retryable import OutOfOrderRetryable

# from .statements.unused_import import UnusedImport
DETECTORS = [
    Backdoor,  # Potential hidden/obfuscated backdoor
    LockedEther,  # Contract can receive ETH but has no withdraw
    UninitializedStateVarsDetection,  # Uninitialized state variables
    UninitializedStorageVars,  # Uninitialized storage variables
    UninitializedLocalVars,  # Uninitialized local variables
    ArbitrarySendEth,  # Arbitrary ETH transfer by any user
    ArbitrarySendErc20NoPermit,  # Arbitrary ERC20 transfer (no permit)
    ArbitrarySendErc20Permit,  # Arbitrary ERC20 transfer (with permit)
    Suicidal,  # Contract can selfdestruct by anyone
    ReentrancyBenign,  # Potential reentrancy (benign)
    ReentrancyReadBeforeWritten,  # Potential reentrancy (read-before-write pattern)
    ReentrancyEth,  # ETH-centric reentrancy
    ReentrancyNoGas,  # Reentrancy with no gas left
    ReentrancyEvent,  # Reentrancy flagged via event usage
    TxOrigin,  # Use of tx.origin for auth (insecure)
    Assembly,  # Inline assembly can hide vulnerabilities
    LowLevelCalls,  # Usage of call()/delegatecall() etc.
    UncheckedTransfer,  # Missing return-value checks on token transfers
    ControlledDelegateCall,  # delegatecall that can be controlled by external input
    UncheckedLowLevel,  # Low-level calls not checked for result
    UncheckedSend,  # send() not checked for success
    Timestamp,  # Usage of block.timestamp for critical logic
    UnprotectedUpgradeable,  # Upgradeable contract without proper access control
    BadPRNG,  # Insecure or predictable pseudo-randomness
    MissingZeroAddressValidation,  # Missing checks for zero address (common bug in ERC20/721)
    UninitializedFunctionPtrsConstructor,  # Uninitialized function pointers in the constructor
    MappingDeletionDetection,  # Potentially dangerous pattern when deleting mappings
    DomainSeparatorCollision,  # EIP712 domain separator issues
    EncodePackedCollision,  # Potential collisions in abi.encodePacked usage
]

# DETECTORS = [
#     Backdoor, UninitializedStateVarsDetection, UninitializedStorageVars, UninitializedLocalVars,
#     VarReadUsingThis, ConstantPragma, IncorrectSolc, LockedEther, ArbitrarySendEth,
#     ArbitrarySendErc20NoPermit, ArbitrarySendErc20Permit, Suicidal, ReentrancyBenign,
#     ReentrancyReadBeforeWritten, ReentrancyEth, ReentrancyNoGas, ReentrancyEvent, UnusedStateVars,
#     CouldBeConstant, CouldBeImmutable, TxOrigin, Assembly, LowLevelCalls, UnusedReturnValues,
#     UncheckedTransfer, NamingConvention, ExternalFunction, ControlledDelegateCall,
#     ConstantFunctionsAsm, ConstantFunctionsState, ShadowingAbstractDetection, StateShadowing,
#     LocalShadowing, BuiltinSymbolShadowing, Timestamp, MultipleCallsInLoop, IncorrectStrictEquality,
#     IncorrectERC20InterfaceDetection, IncorrectERC721InterfaceDetection,
#     UnindexedERC20EventParameters, DeprecatedStandards, RightToLeftOverride, TooManyDigits,
#     UncheckedLowLevel, UncheckedSend, VoidConstructor, TypeBasedTautology, BooleanEquality,
#     BooleanConstantMisuse, DivideBeforeMultiply, UnprotectedUpgradeable, NameReused,
#     UnimplementedFunctionDetection, MappingDeletionDetection, ArrayLengthAssignment,
#     FunctionInitializedState, RedundantStatements, BadPRNG, CostlyOperationsInLoop,
#     AssertStateChange, MissingInheritance, ShiftParameterMixup, StorageSignedIntegerArray,
#     UninitializedFunctionPtrsConstructor, ABIEncoderV2Array, ArrayByReference, EnumConversion,
#     MultipleConstructorSchemes, PublicMappingNested, ReusedBaseConstructor,
#     MissingEventsAccessControl, MissingEventsArithmetic, ModifierDefaultDetection,
#     PredeclarationUsageLocal, IncorrectUnaryExpressionDetection, MissingZeroAddressValidation,
#     DeadCode, WriteAfterWrite, MsgValueInLoop, DelegatecallInLoop, ProtectedVariables,
#     DomainSeparatorCollision, Codex, CyclomaticComplexity, CacheArrayLength, IncorrectUsingFor,
#     EncodePackedCollision, IncorrectReturn, ReturnInsteadOfLeave, IncorrectOperatorExponentiation,
#     TautologicalCompare, ReturnBomb, OutOfOrderRetryable
# ]

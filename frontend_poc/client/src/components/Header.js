import React, { useState } from "react";
import { Link, NavLink } from "react-router-dom";
import { FileText, Home, Shield } from "lucide-react";
import logo from "../assets/logo.png";

const Header = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const closeMenu = () => setIsMenuOpen(false);

  return (
    <header className="site-header">
      <div className="site-header-inner">
        <div className="header-left">
          <Link to="/" className="brand-link" onClick={closeMenu}>
            <img src={logo} alt="SmartGuard AI Logo" className="brand-logo" />
            <span className="brand-copy"><span className="brand-name">SmartGuard <em>AI</em></span><small>Secure. Analyze. Protect.</small></span>
          </Link>
        </div>

        <div className="header-center">
          <nav className={`site-nav ${isMenuOpen ? "is-open" : ""}`} aria-label="Primary navigation">
            <button
              type="button"
              className="nav-toggle"
              aria-label="Toggle navigation"
              aria-expanded={isMenuOpen}
              onClick={() => setIsMenuOpen((open) => !open)}
            >
              <span className="nav-toggle-label">Menu</span>
              <span className="nav-toggle-icon" aria-hidden="true">
                <span />
                <span />
                <span />
              </span>
            </button>

            <ul className="site-nav-list">
              <li><NavLink to="/" end className={({ isActive }) => `nav-link ${isActive ? "is-active" : ""}`} onClick={closeMenu}><Home size={17} />Home</NavLink></li>
              <li><NavLink to="/vulnerabilities" className={({ isActive }) => `nav-link ${isActive ? "is-active" : ""}`} onClick={closeMenu}><Shield size={17} />Vulnerabilities</NavLink></li>
              <li><NavLink to="/secure-generator" className={({ isActive }) => `nav-link ${isActive ? "is-active" : ""}`} onClick={closeMenu}><FileText size={17} />Secure Contract Generator</NavLink></li>
            </ul>
          </nav>
        </div>

      </div>
    </header>
  );
};

export default Header;

import React from 'react';
import Logo from '../styles/img/upchiapas.png';

const Buscar = ({ searchValue, handleSearchChange, fetchSniffData }) => {
  return (
    <nav>
      <a href="#" className="nav-link">Busca</a>
      <form onSubmit={(e) => {
          e.preventDefault();
          fetchSniffData();
          return false;
        }}>
        <div className="form-input2">
          <input
            type="search"
            placeholder="fecha (YYYY-MM-DD)"
            value={searchValue}
            onChange={handleSearchChange}
          />
          <button type="submit" class="search-btn"><i class="bx bx-search"></i></button>
         
        </div>
      </form>
      <input type="checkbox" id="switch-mode" hidden />
      <label for="switch-mode" className="switch-mode"></label>
      <a href="#" className="profile">
        <img src={Logo}></img>
      </a>
    </nav>
  );
};

export default Buscar;

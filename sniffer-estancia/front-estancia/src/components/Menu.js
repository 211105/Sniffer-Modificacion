import React, { useState, useEffect } from 'react';
import Table from '../pages/Sniffer';
import { Link } from 'react-router-dom';
import Aceptar from '../pages/UserAdmin';
import NotFound from '../pages/NotFound';


const Menu = () => {
  const miValorBooleano = localStorage.getItem("miValorBooleano") === "true";
  console.log("local es. " + miValorBooleano)
 // const [userDataa, setUserDataa] = useState(JSON.parse(localStorage.getItem('userData')));
  const showSettingsButton = miValorBooleano;

  const storedData = JSON.parse(localStorage.getItem('userData'));

  const [userData, setUserData] = useState(() => {

    const storedIdentifier = localStorage.getItem('userIdentifier');
  
    // Si el identificador almacenado coincide con el identificador actual,
    // devolvemos los datos almacenados.
    if (storedIdentifier === getIdentifier()) {
      return storedData;
    }
  
    // Si no, eliminamos los datos almacenados y devolvemos null.
    localStorage.removeItem('userData');
    return null;
  });
  
  // Función para obtener el identificador único del usuario.
  function getIdentifier() {
    let identifier = localStorage.getItem('userIdentifier');
  
    if (!identifier) {
      identifier = Math.random().toString(36).substr(2, 9);
      localStorage.setItem('userIdentifier', identifier);
    }
  
    return identifier;
  }
  const [isAppClosing, setIsAppClosing] = useState(false);

  useEffect(() => {
    const onBeforeUnload = (event) => {
      if (!isAppClosing) {
        // Si la aplicación no se está cerrando, no eliminamos los datos del localStorage
        return;
      }
  
      // Aquí puedes realizar cualquier limpieza que necesites antes de que la página se cierre
      localStorage.removeItem('userData');
    }
  
    window.addEventListener('beforeunload', onBeforeUnload);
  
    return () => {
      window.removeEventListener('beforeunload', onBeforeUnload);
    }
  }, [isAppClosing]);
  



  const [sidebarHidden, setSidebarHidden] = useState(true);
  const [activeMenuItem, setActiveMenuItem] = useState(0); // cambiar a 0
  const [showTable, setShowTable] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const handleSidebarToggle = () => {
    setSidebarHidden(!sidebarHidden);
  };

  const handleMenuItemClick = (index) => {
    setActiveMenuItem(index);
  };
  useEffect(() => {
    const allSideMenu = document.querySelectorAll('#sidebar .side-menu.top li a');
    allSideMenu.forEach((item, index) => {
      const li = item.parentElement;
      item.addEventListener('click', () => {
        allSideMenu.forEach((i) => {
          i.parentElement.classList.remove('active');
        });
        li.classList.add('active');
        handleMenuItemClick(index);
      });
    });
  }, []);
  const LongOut = () => {
    localStorage.removeItem('userData');

  }
  const [brandClass, setBrandClass] = useState('brand2 large');

  useEffect(() => {
    if (userData && userData.nombre_completo) {
      const nombre_completo = userData.nombre_completo.trim();
      if (nombre_completo.length > 20) {
        setBrandClass('brand2 small');
      } else {
        setBrandClass('brand2 large');
      }
    }
  }, [userData]);
  return (
    <div >
      {userData ? (
        <di>
          <section id="sidebar" className={sidebarHidden ? 'hide' : ''}>
            <a href="#" className="brand">
              <i className='bx bx-menu' onClick={handleSidebarToggle} ></i>
              {userData && (
                <span className={brandClass}>{userData.nombre_completo}</span>
              )}

            </a>
            <div className="user-info bg-light p-3">

            </div>


            <div className="side-menu top">
              <li>
                <a href="#" className={activeMenuItem === 0 ? 'active' : ''}>
                  <i className='bx bxs-dashboard' ></i>

                  <span className="text">Sniffer</span>
                </a>

              </li>
              {showSettingsButton && (
                <li>
                  <a href="#" className={activeMenuItem === 1 ? 'active' : ''}>
                    <i className='bx bxs-cog' ></i>
                    <span className="text">Settings</span>
                  </a>
                </li>
              )}

            </div>
            <div className="side-menu" >

              <li>
                <Link to="/" onClick={LongOut} className="logout" >
                  <i className='bx bxs-log-out-circle' ></i>
                  <span className="text">Logout</span>
                </Link>
              </li>
            </div>

          </section>



          <section id="content" >
            {activeMenuItem === 0 ? <Table /> : <Aceptar />}
          </section>
        </di>
      ) : (
        <NotFound />
      )}


    </div>

  )
}
export default Menu;

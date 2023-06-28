import NotFound from '../styles/img/404.png'
import '../styles/NotFound.css'
import { Link } from 'react-router-dom';

const Error404 = () => {
    return (
      
            <header>
                <div className="circle move" data-value="-1"></div>
                <div className="circle move" data-value="-1"></div>
                <div className="circle move" data-value="-1"></div>
                <div className="circle move" data-value="-1"></div>


                <div className="container2">
                    <p>¿Perdido en la galaxia WiFi?</p>
                    <h1>404</h1>
                    <Link to='/'>Regresa</Link>
                    <img src={NotFound} alt="Astronaut_img" />
                </div>
            </header>
      
    )
}
export default Error404;
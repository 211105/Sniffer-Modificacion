import avatar from '../styles/img/laptop.png'
import PictureLogin from '../styles/img/PictureLogin.png'
import wave from '../styles/img/wave.png'
import { Link, useNavigate } from 'react-router-dom';
import { useForm } from "react-hook-form";
import { useState, useEffect } from 'react';
import axios from 'axios';
import Swal from 'sweetalert2';

const SignUpMaster = () => {
    const navigator = useNavigate()

    const PIN = "123";

    useEffect(() => {
        const showPinPrompt = () => {
          Swal.fire({
            title: 'Ingresa el Pin',
            input: 'password',
            inputAttributes: {
              autocapitalize: 'off'
            },
            showCancelButton: true,
            confirmButtonText: 'Ingresar',
            cancelButtonText: 'Cancelar',
            allowOutsideClick: false
          }).then((result) => {
            if (result.isConfirmed) {
              if (result.value === PIN) {
                console.log('Pin correcto');
              } else {
                Swal.fire({
                  icon: 'error',
                  title: 'Error',
                  text: 'Pin incorrecto, inténtalo de nuevo'
                }).then(() => {
                  showPinPrompt();
                });
              }
            } else if (result.dismiss === Swal.DismissReason.cancel) {
                navigator("/");

            }
          });
        }
      
        showPinPrompt();
      }, []);
      
    const [response, setResponse] = useState('');

    const { handleSubmit, register, formState: { errors } } = useForm();
    const [userData, setUserData] = useState(JSON.parse(localStorage.getItem('userData')));
    useEffect(() => {
      const userData = JSON.parse(localStorage.getItem('userData'));
      if (!userData) {
      } else if (window.location.pathname !== '/Home') {
        navigator("/Home");
      }
    }, []);
    const handleSignUp = async (data) => {
        try {
          const response = await axios.post('http://localhost:5000/userMaster', data);
          console.log(response.data);
          setResponse(response.data.mensaje);
        } catch (error) {
          console.error(error.response.data);
          setResponse(error.response.data.mensaje);
        }
      }
      
    return (
        <div>
            <img className='wave' src={wave}></img>
            <div className='container'>
                <div className='img'>
                    <img src={PictureLogin}></img>
                </div>

                <div className='login-content'>
                    <form onSubmit={handleSubmit(handleSignUp)}>
                        <img src={avatar}></img>
                        <h2 className="title">SignUp Master</h2>
                        <div className="form-group">
                            <input
                                type="text"
                                className="form-input"
                                id="full_name"
                                placeholder="nombre completo"
                                {...register("full_name", {
                                    required: "Este campo es requerido",
                                    minLength: {
                                        value: 6,
                                        message: "El nombre completo debe tener al menos 6 letras",
                                    },
                                    pattern: {
                                        value: /^[a-zA-Z ]+$/,
                                        message: "El nombre completo no debe tener números",
                                    },
                                })}
                            />

                            {errors.full_name && (
                                <span className="text-danger">{errors.full_name.message}</span>
                            )} <label htmlFor="text" className="form-label">
                                nombre completo
                            </label>
                        </div>
                        <div className="form-group">
                            <input
                                type="text"
                                className="form-input"
                                id="email"
                                placeholder="Correo"
                                {...register("email", {
                                    required: "Este campo es requerido",
                                    pattern: {
                                        value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                                        message: "Correo inválido",
                                    },
                                })}
                            />
                            {errors.email && (
                                <span className="text-danger">{errors.email.message}</span>
                            )}
                            <label htmlFor="correo" className="form-label">
                                Correo
                            </label>
                        </div>
                        <div className="form-group">
                            <input
                                type="password"
                                className="form-input"
                                id="password"
                                placeholder="Contraseña"
                                {...register("password", {
                                    required: "Este campo es requerido",
                                    minLength: {
                                        value: 4,
                                        message: "La contraseña debe tener mínimo 4 caracteres",
                                    },
                                    pattern: {
                                        value: /(?=.*[A-Z])(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&_-]{4,}/,
                                        message:
                                            "La contraseña debe tener mínimo una letra mayúscula y un símbolo @$!%*?&",
                                    },
                                })}
                            />
                            {errors.password && (
                                <span className="text-danger">{errors.password.message}</span>
                            )}
                            <label htmlFor="contraseña" className="form-label">
                                Contraseña
                            </label>


                        </div>

                        <div className="form-group">
                            <input
                                type="text"
                                className="form-input"
                                id="phone"
                                placeholder="telefono"
                                {...register("phone", {
                                    required: "Este campo es requerido",
                                    pattern: {
                                        value: /^[0-9]{10}$/,
                                        message: "El número de teléfono debe tener 10 dígitos y no aceptar letras"
                                    }
                                })}
                            />
                            {errors.phone && (
                                <span className="text-danger">{errors.phone.message}</span>
                            )}
                            <label htmlFor="telefono" className="form-label">
                                telefono
                            </label>
                        </div>
                        <Link to="/">iniciar sesión</Link>


                        <button type="submit" className="form-submit" onClick={handleSubmit(handleSignUp)}>

                            SignUp
                        </button>
                        {response && (
                            <div className="response-message">{response}</div>
                        )}

                    </form>
                </div>

            </div>
        </div>

    )
}
export default SignUpMaster;
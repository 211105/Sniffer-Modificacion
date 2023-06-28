import React, { useState, useEffect } from 'react';
import Swal from 'sweetalert2';
import Buscar from './search';
import Logo from '../styles/img/upchiapas.png';
import user from '../styles/img/laptop.png';

const Aceptar = () => {
	const [sniffData, setSniffData] = useState([]);

	useEffect(() => {
		fetch('http://localhost:5000/users')
			.then(response => response.json())
			.then(data => {
				setSniffData(data);
			})
			.catch(error => console.log(error));
	}, []);

	const handleDelete = id => {
		Swal.fire({
			title: '¿Estás seguro de que quieres eliminar este usuario?',
			text: '¡Esta acción no se puede deshacer!',
			icon: 'warning',
			showCancelButton: true,
			confirmButtonColor: '#3085d6',
			cancelButtonColor: '#d33',
			confirmButtonText: 'Sí, eliminar',
			cancelButtonText: 'Cancelar'
		}).then(result => {
			if (result.isConfirmed) {
				// Eliminar el usuario de la base de datos y actualizar el estado
				fetch(`http://localhost:5000/users/${id}`, {
					method: 'DELETE'
				})
					.then(response => response.json())
					.then(() => {
						setSniffData(prevState =>
							prevState.filter(user => user.id !== id)
						);
						Swal.fire({
							title: '¡Usuario eliminado!',
							icon: 'success'
						});
					})
					.catch(error => console.log(error));
			}
		});
	};

	return (
		<>
			<nav>
				<a href="#" className="profile">
					<img src={Logo} alt="Logo de UP Chiapas" />
				</a>
			</nav>
			<main>
				<div className="table-data">
					<div className="order">
						<div className="head">
							<h3>Usuarios</h3>

						</div>


						
						<div className='row'>
							{sniffData.map(data => (

								
									<div class='product--blue' key={data.id}>
										<div class='product_inner'>
											<img src={user} width='300' />
											<p>{data.full_name}</p>
											<p>{data.email}</p>
											<p>{data.phone}</p>
											<p>{data.password}</p>
											<button onClick={() => handleDelete(data.id)}>Eliminar</button>
										</div>
										<div class='product_overlay'>
											<h2>Added to basket</h2>
											<i class='fa fa-check'></i>
										</div>
									</div>



								
							))}
						</div>
					</div>

				</div>
			</main>
		</>
	);
};

export default Aceptar;

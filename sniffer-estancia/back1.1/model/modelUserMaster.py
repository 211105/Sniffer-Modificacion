from config.config import conexion

def crear_tabla():
    cursor = conexion.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usersMaster (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(50),
        password VARCHAR(50),
        full_name VARCHAR(100),
        phone VARCHAR(20)
    )
    """)

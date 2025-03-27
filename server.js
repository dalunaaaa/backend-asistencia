require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración de CORS
app.use(cors({
  origin: 'http://127.0.0.1:5500',
  methods: ['GET', 'POST', 'PUT'],
  credentials: true
}));
app.use(express.json());

// Pool de conexiones MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'colegio_asistencia',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware de autenticación JWT
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Token no proporcionado' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const [user] = await pool.query('SELECT id FROM Profesores WHERE id = ?', [decoded.id]);
    if (!user) return res.status(403).json({ error: 'Usuario no válido' });
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Token inválido' });
  }
};

// Controladores
const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const [[profesor]] = await pool.query('SELECT * FROM Profesores WHERE email = ?', [email]);
    
    if (!profesor || !(await bcrypt.compare(password, profesor.password))) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const token = jwt.sign(
      { id: profesor.id, email: profesor.email },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ token, nombre: `${profesor.nombre} ${profesor.apellido}` });
  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ error: 'Error en el servidor' });
  }
};

const registrarAsistencia = async (req, res) => {
  try {
    const { alumnos } = req.body;
    const fecha = new Date().toISOString().split('T')[0];

    await pool.query('START TRANSACTION');
    for (const alumno of alumnos) {
      await pool.query(
        `INSERT INTO Asistencia (alumno_id, profesor_id, fecha, estado)
         VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE estado = VALUES(estado)`,
        [alumno.id, req.user.id, fecha, alumno.estado]
      );
    }
    await pool.query('COMMIT');
    res.json({ success: true });
  } catch (err) {
    await pool.query('ROLLBACK');
    console.error('Error registrando asistencia:', err);
    res.status(500).json({ error: 'Error al guardar asistencia' });
  }
};

const obtenerAlumnosPorGrado = async (req, res) => {
  try {
    const [alumnos] = await pool.query(`
      SELECT a.id, a.nombre, a.apellido, g.nombre as grado 
      FROM Alumnos a
      JOIN Grados g ON a.grado_id = g.id
      WHERE a.grado_id = ?
    `, [req.params.grado_id]);
    res.json(alumnos);
  } catch (err) {
    console.error('Error obteniendo alumnos:', err);
    res.status(500).json({ error: 'Error en la base de datos' });
  }
};

// Rutas
app.post('/auth/login', login);
app.post('/asistencia/marcar', authenticateToken, registrarAsistencia);
app.get('/alumnos/grado/:grado_id', authenticateToken, obtenerAlumnosPorGrado);

// Ruta para registrar asistencia 
app.post('/asistencia/marcar', authenticateToken, registrarAsistencia);

// Ruta para consultar asistencia 
app.get('/asistencia', authenticateToken, (req, res) => {
 
  res.json({ data: [] }); 
});

// Iniciar servidor
app.listen(PORT, () => console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`));     
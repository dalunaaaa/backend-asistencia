require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración CORS
const corsOptions = {
  origin: ['http://localhost:5500', 'http://127.0.0.1:5500'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
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

// Middleware de autenticación
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret_key');
    const [user] = await pool.query('SELECT id FROM Profesores WHERE id = ?', [decoded.id]);
    
    if (!user.length) return res.sendStatus(403);
    
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token error:', err);
    res.status(403).json({ error: 'Token inválido' });
  }
};

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });

    const [[profesor]] = await pool.query('SELECT * FROM Profesores WHERE email = ?', [email]);
    if (!profesor) return res.status(401).json({ error: 'Credenciales inválidas' });

    const match = await bcrypt.compare(password, profesor.password);
    if (!match) return res.status(401).json({ error: 'Credenciales inválidas' });

    const token = jwt.sign(
      { id: profesor.id, email: profesor.email },
      process.env.JWT_SECRET || 'secret_key',
      { expiresIn: '8h' }
    );

    res.json({ 
      token,
      nombre: `${profesor.nombre} ${profesor.apellido}`,
      id: profesor.id
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Registrar asistencia
app.post('/api/asistencia/registrar', authenticateToken, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const { registros } = req.body;
    const fecha = new Date().toISOString().split('T')[0];

    if (!Array.isArray(registros)) {
      await connection.rollback();
      return res.status(400).json({ error: 'Datos inválidos' });
    }

    for (const alumno of registros) {
      if (!alumno.alumnoId || !alumno.estado) {
        await connection.rollback();
        return res.status(400).json({ error: 'Datos incompletos' });
      }

      await connection.query(
        `INSERT INTO Asistencia (alumno_id, profesor_id, fecha, estado)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE estado = VALUES(estado)`,
        [alumno.alumnoId, req.user.id, fecha, alumno.estado]
      );
    }

    await connection.commit();
    res.json({ success: true });
  } catch (err) {
    if (connection) await connection.rollback();
    console.error('Error al guardar asistencia:', err);
    res.status(500).json({ error: 'Error al guardar asistencia' });
  } finally {
    if (connection) connection.release();
  }
});

// Obtener alumnos por grado
app.get('/api/alumnos/grado/:gradoId', authenticateToken, async (req, res) => {
  try {
    const [alumnos] = await pool.query(`
      SELECT a.id, a.nombre, a.apellido, g.nombre as grado 
      FROM Alumnos a
      JOIN Grados g ON a.grado_id = g.id
      WHERE a.grado_id = ?
    `, [req.params.gradoId]);

    res.json(alumnos);
  } catch (err) {
    console.error('Error al obtener alumnos:', err);
    res.status(500).json({ error: 'Error al obtener alumnos' });
  }
});

// Verificar token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

app.listen(PORT, () => console.log(`🚀 Servidor en http://localhost:${PORT}`));
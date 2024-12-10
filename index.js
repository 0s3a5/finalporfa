import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import { neon } from '@neondatabase/serverless';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CLAVE_SECRETA = process.env.CLAVE_SECRETA || 'sedavueltaelsemestre123';
const AUTH_COOKIE_NAME = 'segurida';
const sql = neon(process.env.DATABASE_URL || 'postgresql://pagina_owner:ACPjs2Bh7ovH@ep-royal-meadow-a5sckxt7.us-east-2.aws.neon.tech/pagina?sslmode=require');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(express.static(path.join(__dirname, 'public')));
const authMiddleware = async (req, res, next) => {
  const token = req.cookies[AUTH_COOKIE_NAME];
  try {
    req.user = jwt.verify(token, CLAVE_SECRETA);
    next();
  } catch (e) {
    res.status(401).json({ error: 'No autorizado' });
  }
};
app.put('/producto/:id', async (req, res) => {
  console.log("Solicitud recibida para actualizar producto:", req.params.id);
  const { id } = req.params;
  const { nombre, descripcion, link_imagen, precio, cantidad } = req.body;

  // Validar datos requeridos
  if (!id || !nombre || !descripcion || !link_imagen || !precio || !cantidad) {
      console.error("Faltan datos requeridos en la solicitud.");
      return res.status(400).json({ error: 'Datos inválidos. Verifica los campos enviados.' });
  }

  try {
      // Construir la consulta SQL para actualizar
      const query = `
          UPDATE producto
          SET 
              nombre = $1,
              descripcion = $2,
              link_imagen = $3,
              precio = $4,
              cantidad = $5
          WHERE id = $6
          RETURNING *;
      `;
      
      const result = await sql(query, [nombre, descripcion, link_imagen, precio, cantidad, id]);

      // Verificar si el producto fue encontrado y actualizado
      if (result.length === 0) {
          console.warn(`Producto con ID ${id} no encontrado.`);
          return res.status(404).json({ error: 'Producto no encontrado.' });
      }

      console.log("Producto actualizado exitosamente:", result[0]);
      res.status(200).json({
          message: 'Producto actualizado exitosamente.',
          producto: result[0]
      });
  } catch (error) {
      console.error('Error en la operación de base de datos:', error);
      res.status(500).json({
          error: 'Error en el servidor.',
          detalle: error.message
      });
  }
});


app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'home.html'));
});
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});
app.get('/homeuser', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'homeuser.html'));
});
app.get('/paginapeluche', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'paginapeluche.html'));
});
app.get('/agregararma', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'agregararma.html'));
});
app.get('/direccionador', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'direccionador.html'));
});

app.get('/direccionadorr', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'direccionadorr.html'));
});


app.get('/homeADMIN', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'homeADMIN.html'));
});
app.get('/registrarse', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'registrarse.html'));
});
app.get('/editar', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'editar.html'));
});
app.get('/carrito', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'carrito.html'));
});
app.get('/sesionuser', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'sesionuser.html'));
});

app.get('/wallet', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'wallet.html'));
});
app.get('/main', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'main.html'));
});
app.get('/newcarrito', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'new.carrito.html'));
});
app.post('/add-to-carrito', async (req, res) => { //añadir un productos al carrito
  const { id_producto, cantidad } = req.body;

  try {
      const token = req.cookies.auth_token;
      const decoded = jwt.verify(token, secretKey);
      const id_usuario = decoded.userId;

      const existeProducto = await pool.query(
         ' SELECT * FROM carrito WHERE id_usuario = $1 AND id_producto = $2',
          [id_usuario, id_producto]
      );

      if (existeProducto.rows.length > 0) {
          await pool.query(
              'UPDATE carrito SET cantidad = cantidad + $1 WHERE id_usuario = $2 AND id_producto = $3',[cantidad, id_usuario, id_producto]
          );
      } else {
          await pool.query(
              'INSERT INTO carrito (id_usuario, id_producto, cantidad) VALUES ($1, $2, $3)',
              [id_usuario, id_producto, cantidad]
          );
      }

      res.status(200).json({ message: 'Producto añadido al carrito' });
  } catch (error) {
      console.error('Error al añadir producto al carrito:', error);
      res.status(500).json({ error: 'Error al añadir producto al carrito' });
  }
});

app.put('/carrito/:id_producto', async (req, res) => { //actualizar un producto en el carrito
  try {
      const token = req.cookies.auth_token;
      if (!token) return res.status(401).json({ error: 'Usuario no autenticado' });

      const decoded = jwt.verify(token, secretKey);
      const id_usuario = decoded.userId;
      const { cantidad } = req.body;
      const id_producto = req.params.id_producto;

      if (cantidad === 0) {
          await pool.query('DELETE FROM carrito WHERE id_usuario = $1 AND id_producto = $2', [id_usuario, id_producto]);
          return res.status(200).json({ message: 'Producto eliminado del carrito' });
      } else {
          // Si la cantidad es mayor a 0, actualizar la cantidad
          await pool.query('UPDATE carrito SET cantidad = $1 WHERE id_usuario = $2 AND id_producto = $3', [cantidad, id_usuario, id_producto]);
          return res.status(200).json({ message: 'Cantidad actualizada correctamente' });
      }
  } catch (error) {
      console.error('Error al actualizar el carrito:', error);
      res.status(500).json({ error: 'Error del servidor' });
  }
});
app.get('/leer-carrito', async (req, res) => { //leer el carrito
  try {
      const token = req.cookies.auth_token;
      if (!token) return res.status(401).json({ error: 'Usuario no autenticado' });

      const decoded = jwt.verify(token, secretKey);
      const id_usuario = decoded.userId;

      const result = await pool.query(
          'SELECT p.id_producto, p.nombre, p.precio, c.cantidad, p.image_url FROM carrito c JOIN productos p ON c.id_producto = p.id_producto WHERE c.id_usuario = $1',
          [id_usuario]
      );
      res.status(200).json({ carrito: result.rows });
  } catch (error) {
      console.error('Error al obtener el carrito:', error);
      res.status(500).json({ error: 'Error del servidor' });
  }
});
app.post('/comprar-todo', async (req, res) => { //comprar todo el carrito
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ error: 'Usuario no autenticado' });

  let userId;
  try {
      const decoded = jwt.verify(token, secretKey);
      userId = decoded.userId; 
  } catch (error) {
      return res.status(401).json({ error: 'Token inválido' });
  }

  const client = await pool.connect();

  try {
      await client.query('BEGIN');

      const saldoRes = await client.query('SELECT saldo FROM wallet WHERE id_usuario = $1', [userId]);
      console.log('Resultado de saldoRes:', saldoRes.rows);

      if (saldoRes.rows.length === 0) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'No se encontró la wallet del usuario.' });
      }

      const saldo = saldoRes.rows[0].saldo;

      const carritoRes = await client.query('SELECT c.id_producto, c.cantidad, p.precio FROM carrito c JOIN productos p ON c.id_producto = p.id_producto WHERE c.id_usuario = $1', [userId]);
      const carrito = carritoRes.rows;

      let totalCompra = 0;
      carrito.forEach(item => {
          totalCompra += item.precio * item.cantidad;
      });

      if (saldo < totalCompra) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Saldo insuficiente para realizar la compra.' });
      }

      const ordenRes = await client.query('INSERT INTO ordenes (id_usuario, total) VALUES ($1, $2) RETURNING id_orden', [userId, totalCompra]);
      const idOrden = ordenRes.rows[0].id_orden;


      for (const item of carrito) {
          await client.query('INSERT INTO detalle_orden (id_orden, id_producto, cantidad, precio) VALUES ($1, $2, $3, $4)', [idOrden, item.id_producto, item.cantidad, item.precio]);

          await client.query('UPDATE productos SET stock = stock - $1 WHERE id_producto = $2', [item.cantidad, item.id_producto]);
      }

      const nuevoSaldo = saldo - totalCompra;
      await client.query('UPDATE wallet SET saldo = $1 WHERE id_usuario = $2', [nuevoSaldo, userId]);


      await client.query('DELETE FROM carrito WHERE id_usuario = $1', [userId]);

      await client.query('COMMIT');
      res.json({ message: 'Compra realizada con éxito!', idOrden });
  } catch (err) {
      await client.query('ROLLBACK');
      console.error('Error al procesar la compra:', err);
      res.status(500).json({ error: 'Hubo un problema al procesar la compra.' });
  } finally {
      client.release();
  }
});
app.get('/api/producto', async (req, res) => {
  try {
    const id = req.query.paginaid;

    if (!id) {
      return res.status(400).json({ error: 'ID de producto no proporcionado' });
    }

    const producto = await sql('SELECT * FROM producto WHERE id = $1', [id]);

    if (producto.length > 0) { // Verificamos el tamaño del array
      res.json(producto[0]);  // Retornamos el primer resultado
    } else {
      res.status(404).json({ error: 'Producto no encontrado' });
    }
  } catch (error) {
    console.error('Error al obtener el producto:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Endpoint para obtener los datos de un producto por ID
app.get('/api/carrito', async (req, res) => {
  try {
      // Consulta todos los productos de la tabla `ventaencaja`
      const result = await pool.query('SELECT * FROM ventaencaja');
      res.status(200).json(result.rows);
  } catch (error) {
      console.error('Error al obtener los productos del carrito:', error);
      res.status(500).json({ error: 'Error al obtener los productos del carrito.' });
  }
});
app.post('/api/carrito', async (req, res) => {
  console.log("Datos recibidos:", req.body); 
  const { id_producto, nombre_producto, cantidad_producto, precio_producto, imagen_producto, id_asignado } = req.body;

  // Validar los datos
  if (
      !id_producto || !nombre_producto || !imagen_producto || !id_asignado ||
      isNaN(parseInt(cantidad_producto)) || isNaN(parseInt(precio_producto))
  ) {
      return res.status(400).json({ error: 'Datos inválidos. Verifica los campos enviados.' });
  }

  // Calcular el total
  const total = parseInt(cantidad_producto) * parseInt(precio_producto);

  try {
      // Insertar en la tabla `ventaencaja`
      const result = await sql(
          `INSERT INTO ventaencaja (
              nombre_producto, cantidad_producto, precio_producto, id_producto, imagen_producto, total, id_asignado
          ) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
          [nombre_producto, parseInt(cantidad_producto), real(precio_producto), id_producto, imagen_producto, total, id_asignado]
      );

      res.status(201).json({ message: 'Producto añadido al carrito con éxito.', venta: result[0] });
  } catch (error) {
      console.error('Error al añadir al carrito:', error);
      res.status(500).json({ error: 'Error del servidor.' });
  }
});

app.post('/newproduct', async (req, res) => {
  console.log("Cuerpo recibido:", JSON.stringify(req.body, null, 2));
  const { nombre, description, image, datos, price, quantity } = req.body;

  if (!nombre || !description || !image || !datos || !price || !quantity) {
      console.error("Faltan datos en el cuerpo de la solicitud.");
      return res.status(400).json({ error: 'Datos inválidos. Verifica los campos enviados.' });
  }

  try {
      const query = `
          INSERT INTO producto (
            nombre, cantidad, precio, link_imagen, descripcion
          ) VALUES ($1, $2, $3, $4, $5)
          RETURNING *;
      `;
      const result = await sql(query, [nombre, quantity, price, image, description]);

      console.log("Resultado de la base de datos:", result);
      res.status(201).json({
          message: 'Producto agregado exitosamente',
          producto: result[0]
      });
  } catch (error) {
      console.error('Error en la operación de base de datos:', error);
      res.status(500).json({
          error: 'Error en el servidor.',
          detalle: error.message
      });
  }
});
app.get('/producto/:id', async (req, res) => {
  const { id } = req.params; // Obtener el ID del parámetro de la ruta

  try {
      // Realizar la consulta a la base de datos con el ID proporcionado
      const result = await sql('SELECT id AS id_producto, nombre, precio, cantidad, descripcion, link_imagen FROM producto WHERE id = $1', [id]);

      if (result.length > 0) {
          res.json(result[0]); // Si se encuentra, devolver el producto como JSON
      } else {
          res.status(404).json({ error: 'Producto no encontrado' }); // Producto no encontrado
      }
  } catch (error) {
      console.error('Error al consultar la base de datos:', error);
      res.status(500).json({ error: 'Error en el servidor' }); // Manejar errores del servidor
  }
});

app.get('/paginapeluche/:id', async (req, res) => {
  const { id } = req.params;

  if (!id || isNaN(parseInt(id, 10))) {
      return res.status(400).json({ error: 'ID inválido' });
  }

  try {
      const query = 'SELECT id AS id_producto, nombre, precio, cantidad, descripcion, link_imagen FROM producto WHERE id = $1';
      const result = await sql(query, [parseInt(id, 10)]);

      if (result.length === 0) {
          return res.status(404).json({ error: 'Producto no encontrado' });
      }

      res.json(result[0]); // Devolver el producto encontrado
  } catch (error) {
      console.error('Error al consultar la base de datos:', error);
      res.status(500).json({ error: 'Error en el servidor' });
  }
});
app.post('/usuarios', async (req, res) => {
  const { email, password, rango } = req.body;
  const queryCheck = "SELECT * FROM usuarios WHERE email = $1";
  const result = await sql(queryCheck, [email]);
  if (result.length > 0) {
    return res.status(400).json({ error: "El email ya está en uso" });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const query = "INSERT INTO usuarios (rango, email, password, dinero) VALUES ($1, $2, $3, $4)";
  await sql(query, [rango, email, hashedPassword, 10000000]);

  res.status(201).json({ message: "Usuario registrado con éxito" });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Intentando iniciar sesión con:', { email, password });

  try {
    const query = 'SELECT * FROM usuarios WHERE email = $1';
    const results = await sql(query, [email]);

    if (results.length === 0) {
      console.log('No se encontró usuario con ese email.');
      return res.redirect('login.html');
    }

    const user = results[0];
    console.log('Usuario encontrado:', user);

    // Usamos bcrypt.compare para mantener la consistencia con el primer código.
    const isMatch = await bcrypt.compare(password, user.password);
    console.log('Coincidencia de contraseñas:', isMatch);

    if (!isMatch) {
      return res.redirect('login.html');
    }

    const token = jwt.sign({ userId: user.id }, CLAVE_SECRETA, { expiresIn: '1h' });

    res.cookie(AUTH_COOKIE_NAME, token, {
      httpOnly: true,
      maxAge: 3600000,
      secure: process.env.NODE_ENV === 'production', // Asegúrate de tener NODE_ENV configurado
      sameSite: 'strict'
    });

    // Responder con el token y el rol (rango)
    return res.status(200).json({
      message: 'Login exitoso',
      token: token,
      rango: user.rango // Enviamos el rol (rango) del usuario
    });

  } catch (err) {
    console.log('Error durante el login:', err);
    return res.redirect('login.html');
  }
});


app.post('/logout', (req, res) => {
  res.clearCookie(AUTH_COOKIE_NAME);
  res.status(200).json({ message: 'Logout exitoso' });
});

app.get('/productos', async (req, res) => {
  const productos = await sql("SELECT * FROM producto");
  res.status(200).json(productos);
});


app.post('/carrito', authMiddleware, async (req, res) => {
  const { id_producto, cantidad } = req.body;
  const userId = req.user.id;

  const producto = await sql("SELECT * FROM producto WHERE id = $1", [id_producto]);
  if (producto.length === 0) {
    return res.status(404).json({ error: 'Producto no encontrado' });
  }

  const total = producto[0].precio * cantidad;
  await sql(
    "INSERT INTO ventaencaja (id_asignado, id_producto, cantidad_producto, total) VALUES ($1, $2, $3, $4)",
    [userId, id_producto, cantidad, total]
  );

  res.status(201).json({ message: 'Producto agregado al carrito' });
});



app.post('/carrito/checkout', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const carrito = await sql("SELECT * FROM ventaencaja WHERE id_asignado = $1", [userId]);

  if (carrito.length === 0) {
    return res.status(400).json({ error: 'El carrito está vacío' });
  }

  await sql("DELETE FROM ventaencaja WHERE id_asignado = $1", [userId]);
  res.status(200).json({ message: 'Compra finalizada con éxito' });
});

app.post('/usuarios/saldo', authMiddleware, async (req, res) => {
  const { cantidad } = req.body;
  const userId = req.user.id;
  await sql("UPDATE usuarios SET dinero = dinero + $1 WHERE id = $2", [cantidad, userId]);
  res.status(200).json({ message: 'Saldo actualizado con éxito' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Servidor escuchando en http://localhost:${PORT}' );
});
async function obtenerProductos() {
  try {
      const productos = await sql`SELECT * FROM ventaencaja`;
      return productos; // Esto devuelve un array de objetos
  } catch (error) {
      console.error('Error al obtener productos:', error);
      throw error;
  }
}
async function agregarProducto({
  nombre_producto,
  cantidad_producto,
  precio_producto,
  id_producto,
  imagen_producto,
  id_asignado,
}) {
  const total = cantidad_producto * precio_producto;

  try {
      const resultado = await sql`
          INSERT INTO ventaencaja (
              nombre_producto, cantidad_producto, precio_producto, id_producto, imagen_producto, total, id_asignado
          ) VALUES (
              ${nombre_producto}, ${cantidad_producto}, ${precio_producto}, ${id_producto}, ${imagen_producto}, ${total}, ${id_asignado}
          ) RETURNING *`;

      return resultado[0]; // Devuelve el producto insertado
  } catch (error) {
      console.error('Error al agregar producto:', error);
      throw error;
  }
}
async function eliminarProducto(id) {
  try {
      const resultado = await sql`DELETE FROM ventaencaja WHERE id = ${id} RETURNING *`;
      return resultado[0]; // Devuelve el producto eliminado
  } catch (error) {
      console.error('Error al eliminar producto:', error);
      throw error;
  }
}
app.get('/api/listar', async (req, res) => {
  try {
      const productos = await listarProductos();
      res.json(productos);
  } catch (error) {
      res.status(500).json({ error: 'Error al listar productos.' });
  }
});

// Ruta para insertar un producto
app.post('/api/insertar', async (req, res) => {
  try {
      const producto = await insertarProducto(req.body);
      res.status(201).json(producto);
  } catch (error) {
      res.status(500).json({ error: 'Error al insertar producto.' });
  }
});

// Ruta para borrar un producto
app.delete('/api/borrar/:id', async (req, res) => {
  try {
      const producto = await borrarProducto(req.params.id);
      if (!producto) {
          return res.status(404).json({ error: 'Producto no encontrado.' });
      }
      res.json(producto);
  } catch (error) {
      res.status(500).json({ error: 'Error al borrar producto.' });
  }
});
app.post('/add-to-ventaencaja', async (req, res) => {
  const { nombre_producto, cantidad_producto, precio_producto, id_producto, imagen_producto, id_asignado } = req.body;

  try {
      const total = cantidad_producto * precio_producto;

      const existeProducto = await pool.query(
          'SELECT * FROM ventaencaja WHERE id_asignado = $1 AND id_producto = $2',
          [id_asignado, id_producto]
      );

      if (existeProducto.rows.length > 0) {
          await pool.query(
              'UPDATE ventaencaja SET cantidad_producto = cantidad_producto + $1, total = total + $2 WHERE id_asignado = $3 AND id_producto = $4',
              [cantidad_producto, total, id_asignado, id_producto]
          );
      } else {
          await pool.query(
              'INSERT INTO ventaencaja (nombre_producto, cantidad_producto, precio_producto, id_producto, imagen_producto, total, id_asignado) VALUES ($1, $2, $3, $4, $5, $6, $7)',
              [nombre_producto, cantidad_producto, precio_producto, id_producto, imagen_producto, total, id_asignado]
          );
      }

      res.status(200).json({ message: 'Producto añadido a la venta' });
  } catch (error) {
      console.error('Error al añadir producto a ventaencaja:', error);
      res.status(500).json({ error: 'Error al añadir producto a la venta' });
  }
});app.put('/ventaencaja/:id_producto', async (req, res) => {
  const { cantidad_producto, id_asignado } = req.body;
  const id_producto = req.params.id_producto;

  try {
      if (cantidad_producto === 0) {
          await pool.query(
              'DELETE FROM ventaencaja WHERE id_asignado = $1 AND id_producto = $2',
              [id_asignado, id_producto]
          );
          return res.status(200).json({ message: 'Producto eliminado de la venta' });
      } else {
          const producto = await pool.query(
              'SELECT precio_producto FROM ventaencaja WHERE id_asignado = $1 AND id_producto = $2',
              [id_asignado, id_producto]
          );

          if (producto.rows.length === 0) {
              return res.status(404).json({ error: 'Producto no encontrado' });
          }

          const precio_producto = producto.rows[0].precio_producto;
          const total = cantidad_producto * precio_producto;

          await pool.query(
              'UPDATE ventaencaja SET cantidad_producto = $1, total = $2 WHERE id_asignado = $3 AND id_producto = $4',
              [cantidad_producto, total, id_asignado, id_producto]
          );

          return res.status(200).json({ message: 'Cantidad actualizada correctamente' });
      }
  } catch (error) {
      console.error('Error al actualizar ventaencaja:', error);
      res.status(500).json({ error: 'Error del servidor' });
  }
});
app.get('/leer-ventaencaja', async (req, res) => {
  const { id_asignado } = req.query;

  try {
      const result = await pool.query(
          'SELECT * FROM ventaencaja ',
          [id_asignado]
      );
      res.status(200).json({ venta: result.rows });
  } catch (error) {
      console.error('Error al obtener ventaencaja:', error);
      res.status(500).json({ error: 'Error del servidor' });
  }
});
app.post('/comprar-todo-ventaencaja', async (req, res) => {
  const { id_asignado } = req.body;

  const client = await pool.connect();

  try {
      await client.query('BEGIN');

      const ventaRes = await client.query(
          'SELECT * FROM ventaencaja WHERE id_asignado = $1',
          [id_asignado]
      );
      const venta = ventaRes.rows;

      if (venta.length === 0) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'No hay productos en la venta' });
      }

      for (const item of venta) {
          await client.query(
              'UPDATE productos SET stock = stock - $1 WHERE id_producto = $2',
              [item.cantidad_producto, item.id_producto]
          );
      }

      await client.query('DELETE FROM ventaencaja WHERE id_asignado = $1', [id_asignado]);

      await client.query('COMMIT');
      res.json({ message: 'Compra realizada con éxito!' });
  } catch (err) {
      await client.query('ROLLBACK');
      console.error('Error al procesar la compra:', err);
      res.status(500).json({ error: 'Hubo un problema al procesar la compra.' });
  } finally {
      client.release();
  }
});
app.get('/api/usuario', async (req, res) => {
    try {
        const token = req.cookies.auth_token;
        if (!token) {
            return res.json({ loggedIn: false });
        }

        const decoded = jwt.verify(token, secretKey);
        const userResult = await pool.query('SELECT mail, rango FROM usuario WHERE id = $1', [decoded.userId]);

        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];
            return res.json({
                loggedIn: true,
                userEmail: user.mail,
                rango: user.rango,
            });
        } else {
            return res.json({ loggedIn: false });
        }
    } catch (err) {
        console.error('Error verificando el usuario:', err);
        return res.json({ loggedIn: false });
    }
});
app.get('/wallet-balance', async (req, res) => {
    try {
        const token = req.cookies.auth_token; 
        if (!token) {
            return res.status(401).json({ error: 'Usuario no autenticado' });
        }

        const decoded = jwt.verify(token, secretKey); 

        const userId = decoded.userId;
        const result = await pool.query('SELECT dindero FROM usuario WHERE id = $1', [userId]);

        if (result.rows.length > 0) {
            const walletBalance = result.rows[0].dindero; 
            res.json({ saldo: walletBalance }); 
        } else {
            res.status(404).json({ error: 'Usuario no encontrado' });
        }
    } catch (error) {
        console.error('Error al obtener el saldo de la wallet:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});


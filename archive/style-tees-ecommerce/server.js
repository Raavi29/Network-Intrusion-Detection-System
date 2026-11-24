const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize database
const db = new sqlite3.Database('ecommerce.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database');
    // Create orders table if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY,
      customer_name TEXT NOT NULL,
      customer_email TEXT NOT NULL,
      customer_address TEXT NOT NULL,
      customer_city TEXT NOT NULL,
      customer_state TEXT NOT NULL,
      customer_zip TEXT NOT NULL,
      payment_method TEXT NOT NULL,
      items TEXT NOT NULL,
      total REAL NOT NULL,
      order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
      status TEXT DEFAULT 'pending'
    )`, (err) => {
      if (err) {
        console.error('Error creating orders table:', err.message);
      } else {
        console.log('Database table ready');
      }
    });
  }
});

// Middleware
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API: Get products
app.get('/api/products', (req, res) => {
  const products = [
    {
      id: 1,
      name: 'Classic White Tee',
      description: 'Comfortable and versatile white t-shirt perfect for everyday wear',
      price: 29.99,
      sizes: ['S', 'M', 'L', 'XL'],
      image: '👕'
    },
    {
      id: 2,
      name: 'Premium Black Tee',
      description: 'Sleek black t-shirt made from premium cotton blend',
      price: 34.99,
      sizes: ['S', 'M', 'L', 'XL', 'XXL'],
      image: '👕'
    },
    {
      id: 3,
      name: 'Navy Blue Classic',
      description: 'Timeless navy blue t-shirt with modern fit',
      price: 32.99,
      sizes: ['S', 'M', 'L', 'XL'],
      image: '👕'
    },
    {
      id: 4,
      name: 'Gray Premium',
      description: 'Soft gray t-shirt with comfortable relaxed fit',
      price: 31.99,
      sizes: ['S', 'M', 'L', 'XL', 'XXL'],
      image: '👕'
    },
    {
      id: 5,
      name: 'Burgundy Red',
      description: 'Rich burgundy t-shirt for a bold statement',
      price: 35.99,
      sizes: ['M', 'L', 'XL'],
      image: '👕'
    },
    {
      id: 6,
      name: 'Forest Green',
      description: 'Natural forest green t-shirt with eco-friendly materials',
      price: 33.99,
      sizes: ['S', 'M', 'L', 'XL'],
      image: '👕'
    }
  ];
  res.json(products);
});

// API: Create order
app.post('/api/orders', (req, res) => {
  const {
    name,
    email,
    address,
    city,
    state,
    zip,
    paymentMethod,
    items,
    total
  } = req.body;

  // Validate required fields
  if (!name || !email || !address || !city || !state || !zip || !paymentMethod || !items || !total) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const orderId = uuidv4();
  const itemsJson = JSON.stringify(items);

  db.run(
    `INSERT INTO orders (id, customer_name, customer_email, customer_address, customer_city, customer_state, customer_zip, payment_method, items, total)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [orderId, name, email, address, city, state, zip, paymentMethod, itemsJson, total],
    function(err) {
      if (err) {
        console.error('Error inserting order:', err.message);
        return res.status(500).json({ error: 'Failed to save order' });
      }

      console.log(`Order ${orderId} placed: ${name} - $${total}`);
      res.json({
        message: 'Order placed successfully',
        orderId: orderId,
        total: total
      });
    }
  );
});

// API: Get all orders (for admin purposes)
app.get('/api/orders', (req, res) => {
  db.all('SELECT * FROM orders ORDER BY order_date DESC', (err, rows) => {
    if (err) {
      console.error('Error querying orders:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed');
    }
    process.exit(0);
  });
});


const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const session = require("express-session");
const bodyParser = require("body-parser");

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public"));
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: false,
  })
);
app.set("view engine", "ejs");

// Database connection
const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "umkm_weprog",
});

const adminPass = "adminpassword";
bcrypt.hash(adminPass, 10, (err, hash) => {
  if (err) {
    console.error("Error hashing admin password:", err);
    return;
  }
  db.query("INSERT IGNORE INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", ["admin", "admin@example.com", hash, "admin"], (err) => {
    if (err) {
      console.error("Error inserting initial admin user:", err);
    } else {
      console.log("Admin user check/insert finished.");
    }
  });
});

console.log("MySQL Connection Ready...");

// Middleware untuk check login
function isAuthenticated(req, res, next) {
  if (req.session.user) return next();
  res.redirect("/login");
}

// Middleware untuk check admin
function isAdmin(req, res, next) {
  console.log("Checking admin session:", req.session.user);
  if (req.session.user && req.session.user.role === "admin") return next();
  res.status(403).send("Access Denied: Admin only");
}

// Routes

// Home
app.get("/home", (req, res) => {
  const sql = "SELECT * FROM reviews ORDER BY created_at DESC";
  db.query(sql, (err, reviews) => {
    if (err) {
      console.error("Error fetching reviews:", err);
      return res.status(500).send("Terjadi kesalahan server");
    }
    res.render("home", {
      reviews: reviews || [],
      user: req.session.user || null,
    });
  });
});

// Maintenance
app.get("/maintenance", isAuthenticated, (req, res) => {
  res.render("maintenance", { user: req.session.user });
});

// Register
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.render("register", { error: "Semua field harus diisi." });
  }
  db.query("SELECT * FROM users WHERE username = ? OR email = ?", [username, email], (err, results) => {
    if (err) {
      console.error("Registration query error:", err);
      return res.render("register", { error: "Terjadi kesalahan server." });
    }
    if (results.length > 0) {
      return res.render("register", { error: "Username atau email sudah digunakan." });
    }
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        console.error("Hashing error:", err);
        return res.render("register", { error: "Terjadi kesalahan saat registrasi." });
      }
      db.query("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [username, email, hash], (err) => {
        if (err) {
          console.error("Insert user error:", err);
          return res.render("register", { error: "Terjadi kesalahan saat registrasi." });
        }
        res.redirect("/login");
      });
    });
  });
});

// Login
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", (req, res) => {
  const { username, password, action, email } = req.body;
  console.log("Received POST data:", req.body);

  if (action === "register") {
    if (!username || !email || !password) {
      console.log("Validation failed: Missing fields", { username, email, password });
      return res.render("login", { error: "Semua field harus diisi." });
    }
    db.query("SELECT * FROM users WHERE username = ? OR email = ?", [username, email], (err, results) => {
      if (err) {
        console.error("Registration query error:", err);
        return res.render("login", { error: "Terjadi kesalahan server." });
      }
      if (results.length > 0) {
        console.log("Duplicate found:", results);
        return res.render("login", { error: "Username atau email sudah digunakan." });
      }
      bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
          console.error("Hashing error:", err);
          return res.render("login", { error: "Terjadi kesalahan saat registrasi." });
        }
        db.query("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [username, email, hash], (err, result) => {
          if (err) {
            console.error("Insert user error:", err);
            return res.render("login", { error: "Terjadi kesalahan saat registrasi: " + err.message });
          }
          console.log("User registered successfully, ID:", result.insertId);
          res.render("login", { error: "Registrasi berhasil! Silakan login." });
        });
      });
    });
  } else {
    db.query("SELECT * FROM users WHERE username = ?", [username], (err, results) => {
      if (err) {
        console.error("Login query error:", err);
        return res.status(500).send("Server error");
      }
      if (results.length === 0) return res.render("login", { error: "User not found" });
      bcrypt.compare(password, results[0].password, (err, isMatch) => {
        if (err) {
          console.error("Password compare error:", err);
          return res.status(500).send("Server error");
        }
        if (!isMatch) return res.render("login", { error: "Incorrect password" });
        req.session.user = { id: results[0].id, username: results[0].username, role: results[0].role };
        console.log("Login success, user:", req.session.user);
        res.redirect("/products");
      });
    });
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).send("Terjadi kesalahan saat logout");
    }
    res.redirect("/home");
  });
});

// Products
app.get("/products", isAuthenticated, (req, res) => {
  db.query("SELECT * FROM products", (err, products) => {
    if (err) {
      console.error("Products query error:", err);
      return res.status(500).send("Error loading products");
    }
    res.render("products", { products, user: req.session.user });
  });
});

// Detail produk
app.get("/product/:id", isAuthenticated, (req, res) => {
  const productId = req.params.id;
  db.query("SELECT * FROM products WHERE id = ?", [productId], (err, product) => {
    if (err || product.length === 0) {
      console.error("Product detail error:", err);
      return res.status(404).send("Produk tidak ditemukan");
    }
    db.query("SELECT * FROM products WHERE id != ? ORDER BY RAND() LIMIT 3", [productId], (err, recommendations) => {
      if (err) recommendations = [];
      db.query("SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC", [productId], (err, reviews) => {
        if (err) {
          console.error("Error fetching reviews:", err);
          reviews = [];
        }
        res.render("detail", {
          product: product[0],
          recommendations: recommendations,
          reviews: reviews,
          user: req.session.user,
        });
      });
    });
  });
});

// Beli produk
app.post("/purchase/:id", isAuthenticated, (req, res) => {
  const productId = req.params.id;
  const quantity = parseInt(req.body.quantity) || 1;
  const size = req.body.size || "Tidak ditentukan";

  db.query("SELECT stock FROM products WHERE id = ?", [productId], (err, results) => {
    if (err) {
      console.error("Stock query error:", err);
      return res.status(500).send("Error checking stock");
    }
    if (results.length === 0) {
      return res.render("products", { products: [], user: req.session.user, error: "Produk tidak ditemukan" });
    }
    const currentStock = results[0].stock;
    if (currentStock < quantity) {
      return res.render("products", { products, user: req.session.user, error: "Stok tidak cukup" });
    }
    db.query("UPDATE products SET stock = stock - ? WHERE id = ?", [quantity, productId], (err) => {
      if (err) {
        console.error("Update stock error:", err);
        return res.status(500).send("Error updating stock");
      }
      db.query("INSERT INTO purchases (user_id, product_id, quantity, size, purchase_date) VALUES (?, ?, ?, ?, NOW())", [req.session.user.id, productId, quantity, size], (err) => {
        if (err) {
          console.error("Purchase insert error:", err);
          return res.status(500).send("Error recording purchase");
        }
        db.query("SELECT * FROM products", (err, products) => {
          if (err) {
            console.error("Reload products error:", err);
            return res.status(500).send("Error reloading products");
          }
          res.render("products", { products, user: req.session.user, success: true, locals: { success: true } });
        });
      });
    });
  });
});

// Batalkan pembelian (user)
app.post("/cancel-purchase/:id", isAuthenticated, (req, res) => {
  const purchaseId = req.params.id;
  db.query(
    "SELECT p.purchase_date, p.quantity, pr.stock, pr.id AS product_id FROM purchases p JOIN products pr ON p.product_id = pr.id WHERE p.id = ? AND p.user_id = ? AND p.cancelled = 0",
    [purchaseId, req.session.user.id],
    (err, results) => {
      if (err) {
        console.error("Cancel query error:", err);
        return res.status(500).send("Error checking purchase");
      }
      if (results.length === 0) {
        return res.send("Pembelian tidak ditemukan atau sudah dibatalkan");
      }
      const purchase = results[0];
      const now = new Date();
      const purchaseDate = new Date(purchase.purchase_date);
      const timeDiff = (now - purchaseDate) / (1000 * 60 * 60 * 24);
      if (timeDiff > 1) {
        return res.send("Maaf, batas waktu pembatalan (24 jam) telah lewat");
      }
      db.query("UPDATE products SET stock = stock + ? WHERE id = ?", [purchase.quantity, purchase.product_id], (err) => {
        if (err) {
          console.error("Stock rollback error:", err);
          return res.status(500).send("Error updating stock");
        }
        db.query("UPDATE purchases SET cancelled = 1 WHERE id = ?", [purchaseId], (err) => {
          if (err) {
            console.error("Cancel update error:", err);
            return res.status(500).send("Error cancelling purchase");
          }
          res.redirect("/history");
        });
      });
    }
  );
});

// History pembelian (per user)
app.get("/history", isAuthenticated, (req, res) => {
  db.query(
    `
    SELECT p.name, pur.quantity, pur.purchase_date, pur.size, pur.cancelled, pur.id
    FROM purchases pur 
    JOIN products p ON pur.product_id = p.id 
    WHERE pur.user_id = ? AND pur.cancelled = 0\
    `,
    [req.session.user.id],
    (err, history) => {
      if (err) {
        console.error("History query error:", err);
        return res.status(500).send("Error loading history");
      }
      res.render("history", { history, user: req.session.user });
    }
  );
});

// Admin dashboard
app.get("/admin", isAdmin, (req, res) => {
  const user = req.session.user || {};
  db.query("SELECT * FROM products", (err, products) => {
    if (err) {
      console.error("Error fetching products:", err);
      return res.status(500).send("Error loading admin dashboard");
    }
    db.query(
      `
      SELECT u.username, p.name, pur.quantity, pur.purchase_date, pur.size, pur.cancelled, pur.id
      FROM purchases pur
      JOIN users u ON pur.user_id = u.id
      JOIN products p ON pur.product_id = p.id
      WHERE pur.cancelled = 0
       `,
      (err, allPurchases) => {
        if (err) {
          console.error("Error fetching all purchases:", err);
          return res.status(500).send("Error loading admin dashboard");
        }
        db.query("SELECT id, username, email, role FROM users", (err, users) => {
          if (err) {
            console.error("Error fetching users:", err);
            return res.status(500).send("Error loading admin dashboard");
          }
          res.render("admin", { products, users, allPurchases, user });
        });
      }
    );
  });
});

// Edit stok
app.post("/admin/edit-stock/:id", isAdmin, (req, res) => {
  const productId = req.params.id;
  const newStock = parseInt(req.body.stock);
  if (isNaN(newStock)) {
    return res.status(400).send("Invalid stock value");
  }
  db.query("UPDATE products SET stock = ? WHERE id = ?", [newStock, productId], (err) => {
    if (err) {
      console.error("Error updating stock:", err);
      return res.status(500).send("Error updating stock");
    }
    res.redirect("/admin");
  });
});

// Hapus user
app.post("/admin/delete-user/:id", isAdmin, (req, res) => {
  const userId = req.params.id;
  if (userId == req.session.user.id) {
    return res.status(403).send("Cannot delete yourself");
  }
  db.query("DELETE FROM users WHERE id = ?", [userId], (err) => {
    if (err) {
      console.error("Error deleting user:", err);
      return res.status(500).send("Error deleting user");
    }
    res.redirect("/admin");
  });
});

// Endpoint untuk menambahkan ulasan
app.post("/api/reviews", isAuthenticated, (req, res) => {
  console.log("Request body:", req.body);
  const { text, product_id } = req.body;
  const username = req.session.user.username;

  if (!text || text.trim() === "" || !product_id) {
    console.log("Validation failed:", { text, product_id });
    return res.status(400).json({ success: false, error: "Ulasan atau product_id tidak boleh kosong" });
  } // Validasi product_id

  db.query("SELECT id FROM products WHERE id = ?", [product_id], (err, result) => {
    if (err || result.length === 0) {
      console.error("Invalid product_id:", product_id, err);
      return res.status(400).json({ success: false, error: "Produk tidak ditemukan" });
    }

    const sql = "INSERT INTO reviews (review_text, username, product_id, created_at) VALUES (?, ?, ?, NOW())";
    db.query(sql, [text, username, product_id], (err, result) => {
      if (err) {
        console.error("Error inserting review:", err);
        return res.status(500).json({ success: false, error: "Gagal menambahkan ulasan: " + err.message });
      }
      console.log("Review inserted successfully, ID:", result.insertId);
      res.json({ success: true, id: result.insertId });
    });
  });
});

app.delete("/api/reviews/:id", isAuthenticated, (req, res) => {
  const reviewId = req.params.id;
  const user = req.session.user;

  db.query("SELECT * FROM reviews WHERE id = ?", [reviewId], (err, results) => {
    if (err) {
      console.error("Error fetching review:", err);
      return res.status(500).json({ success: false, error: "Terjadi kesalahan server" });
    }
    if (results.length === 0) {
      return res.status(404).json({ success: false, error: "Ulasan tidak ditemukan" });
    }
    const review = results[0];

    if (user.username !== review.username && user.role !== "admin") {
      return res.status(403).json({ success: false, error: "Anda tidak memiliki izin untuk menghapus ulasan ini" });
    }

    db.query("DELETE FROM reviews WHERE id = ?", [reviewId], (err) => {
      if (err) {
        console.error("Error deleting review:", err);
        return res.status(500).json({ success: false, error: "Gagal menghapus ulasan" });
      }
      res.json({ success: true, message: "Ulasan berhasil dihapus" });
    });
  });
});

// Endpoint untuk menghapus pembelian (admin)
app.post("/admin/delete-purchase/:id", isAdmin, (req, res) => {
  const purchaseId = req.params.id;
  db.query("SELECT p.quantity, pr.id AS product_id FROM purchases p JOIN products pr ON p.product_id = pr.id WHERE p.id = ? AND p.cancelled = 0", [purchaseId], (err, results) => {
    if (err) {
      console.error("Delete purchase query error:", err);
      return res.status(500).send("Error checking purchase");
    }
    if (results.length === 0) {
      return res.send("Pembelian tidak ditemukan atau sudah dibatalkan");
    }
    const purchase = results[0];
    db.query("UPDATE products SET stock = stock + ? WHERE id = ?", [purchase.quantity, purchase.product_id], (err) => {
      if (err) {
        console.error("Stock rollback error:", err);
        return res.status(500).send("Error updating stock");
      }
      db.query("UPDATE purchases SET cancelled = 1 WHERE id = ?", [purchaseId], (err) => {
        if (err) {
          console.error("Cancel update error:", err);
          return res.status(500).send("Error cancelling purchase");
        }
        res.redirect("/admin");
      });
    });
  });
});

// Redirect root to /home
app.get("/", (req, res) => {
  res.redirect("/home");
});

app.listen(process.env.PORT || port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

module.exports = app;

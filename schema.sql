CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,                       -- NULL for users who only use social sign-in
  role TEXT NOT NULL DEFAULT 'buyer' CHECK (role IN ('admin','seller','buyer')),
  is_active INTEGER NOT NULL DEFAULT 1,
  email_verified INTEGER NOT NULL DEFAULT 0,   -- 1 once the user clicked the emailed link
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS social_accounts (
  provider TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (provider, provider_id)
);

CREATE TABLE IF NOT EXISTS email_verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,          -- only the hash is stored
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,          -- only the hash is stored
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
-- Stage 2 will add products(seller_id -> users.id) and cart tables.

-- ================= Stage 2 =================
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  price REAL NOT NULL CHECK (price > 0),
  stock INTEGER NOT NULL CHECK (stock >= 0),
  image_filename TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cart_items (          -- one row per (buyer, product)
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  quantity INTEGER NOT NULL CHECK (quantity >= 1),
  PRIMARY KEY (user_id, product_id)
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  total REAL NOT NULL,                           -- grand total (items + delivery), taxes included
  created_at TEXT NOT NULL,
  subtotal REAL, shipping REAL, tax REAL,
  contact_email TEXT, contact_phone TEXT,
  ship_name TEXT, ship_address TEXT, ship_district TEXT, ship_city TEXT,
  payment_method TEXT, payment_status TEXT, momo_number TEXT,
  status TEXT DEFAULT 'Placed',                -- Placed or Cancelled
  cancelled_at TEXT
);

CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
  product_name TEXT NOT NULL,                    -- snapshot, so history survives product deletion
  unit_price REAL NOT NULL,
  quantity INTEGER NOT NULL,
  seller_id INTEGER,                             -- snapshot of the product's seller
  status TEXT DEFAULT 'Placed'                   -- Placed -> Shipped -> Delivered (per line)
);

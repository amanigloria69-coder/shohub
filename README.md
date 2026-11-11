# ShopHub - Smart E-Commerce Platform (Flask)

## Run
    py -m pip install -r requirements.txt
    py create_admin.py        (once - creates the first administrator)
    py app.py                 -> open http://localhost:5000

Upgrading from Stage 1? Keep your shop.db - the new Stage 2 tables are added automatically on start.
Uploaded product images are saved in static/uploads/.

To open the local app from another device on the same Wi-Fi, set `FLASK_HOST=0.0.0.0`
and set `SITE_URL` to the Windows computer's LAN address (for example,
`http://192.168.1.114:5000`). Use that address on the other device. Keep the Flask
debugger disabled when binding to `0.0.0.0`; this app is for local development, not
public hosting. The LAN address can change when reconnecting to Wi-Fi.

## Tests and project deliverables
Run the project test suite from the `shophub` folder:

    py -m unittest discover -s tests -v

The test suite and project documentation cover the e-commerce flows, database relationships, and HCI design.

## Free public demo without losing local data

For a no-cost demo that keeps the existing SQLite database and product images, leave the app and its files on your Windows computer and publish it through a Cloudflare Quick Tunnel. The database remains in `shop.db` and uploaded images in `static/uploads/`; they are not stored on Render's temporary filesystem. Your computer must stay on and connected to the internet while visitors use the site.

1. Install the Python dependencies and [Cloudflare Tunnel (`cloudflared`)](https://developers.cloudflare.com/tunnel/downloads/). In PowerShell, from the `shophub` directory, run `py -m pip install -r requirements.txt`.
2. Open one PowerShell window in the project folder and start a temporary tunnel:

       cloudflared tunnel --url http://localhost:5000

   Copy the `https://...trycloudflare.com` address printed in that window. Keep the tunnel running.
3. Open a second PowerShell window in the same project folder. Set the tunnel address and start the production WSGI server:

       $env:SITE_URL = "https://YOUR-TUNNEL.trycloudflare.com"
       $env:COOKIE_SECURE = "true"
       py -c "from waitress import serve; from wsgi import app; serve(app, listen='127.0.0.1:5000')"

   Replace the example URL with the exact URL from step 2. The WSGI entry point initializes the database schema before serving requests. Keep both windows open.
4. Configure the existing `MAIL_` settings in your local `.env`, then restart the WSGI server. Never share or commit `.env`.
5. Give visitors the tunnel URL. Verification and password-reset links will use that URL. When the tunnel is restarted, Cloudflare Quick Tunnels generate a different URL: repeat step 2, update `SITE_URL`, and restart the app before sending new emails. Old links will point to the old address.

This is free for a temporary presentation, not always-on production hosting. The URL is temporary, the app is unavailable when your computer or either process is off, and a local disk failure could still lose data—make backups of `shop.db` and `static/uploads/`. Anyone who has the public URL can visit the app, so use a strong secret key, keep dependencies updated, and do not expose the Flask debugger.

Render Free is another option for a sleeping public demo, but it discards local files when the service spins down or redeploys. Keeping data there needs separate persistent database and image storage; Render's own free Postgres also has a 30-day limit. See [Render's free instance limitations](https://render.com/docs/free). For permanent always-on hosting, use a paid service with persistent storage and backups.

## 1. Password-reset emails
Without setup, the reset email is printed in the PowerShell window (development mode).
To send real emails, copy `.env.example` to `.env` and fill the MAIL_ lines.
Gmail: turn on 2-Step Verification, create an "App password", and paste it as MAIL_PASSWORD.

## 2. Social sign-in (optional; each one needs its own keys in .env)
Always open the site as http://localhost:5000 (not 127.0.0.1) and register these redirect URLs:
- Google   (console.cloud.google.com > APIs & Services > Credentials > OAuth client ID, Web app)
           http://localhost:5000/auth/google/callback
- LinkedIn (linkedin.com/developers > Create app > add product "Sign In with LinkedIn using OpenID Connect")
           http://localhost:5000/auth/linkedin/callback
- Facebook (developers.facebook.com > Create app > Facebook Login)
           http://localhost:5000/auth/facebook/callback
Copy each Client ID / Secret into `.env`, then restart the app. A provider's button appears only when its keys are in .env (no keys = no button).
In the Google console, add test users or click Publish app so other Gmail accounts (e.g. your lecturer) can sign in.

## Stage 2 - what to demo
- Seller/Admin: register a product (image upload, price must be a positive number, stock a whole number), edit, delete.
- Buyer: catalog grid, product page, Add to Cart, cart counter in the header.
- Cart (live, no page refresh): + / - / typed quantity (cannot exceed stock), trash icon, subtotals, grand total.
- Checkout page: Contact, Payment (Card, MTN MoMo, Cash on Delivery), Delivery address (Rwanda districts), order summary with delivery fee and included taxes (18% VAT).
  Payment is SIMULATED (no real money): Card and MTN MoMo choices save a demo payment status; Cash on Delivery is marked due on delivery. No card details, MoMo number, PIN, or OTP is collected. Stock goes down, the order is saved with its address and payment method (My Orders / order page), a confirmation email is sent, and the cart is emptied.
- Footer on every page (Help Customers, About Us, Contact Us, Privacy Policy, Return Policy, social icons, Live chat button). Set your phone, email and social links in .env (CONTACT_PHONE is also the WhatsApp number; SOCIAL_INSTAGRAM, SOCIAL_TIKTOK).
- When stock reaches 0: "Out of Stock" badge and the Add to Cart button is disabled.
- Role protection: buyers cannot open /products/new; sellers and admins cannot open /cart.
- Orders: a buyer can Cancel an order (stock goes back, payment marked refunded) and then Delete the cancelled order from their history.
- Seller: "Orders" page lists orders containing the seller's products (their lines only, with delivery details); mark Shipped, then Delivered.
- Admin: "Orders" page lists all orders, filter by status, mark all lines Shipped/Delivered, or cancel an order that has not shipped.
- Buyers see Placed / Partially shipped / Shipped / Delivered / Cancelled, get an email at each step, and can cancel only while nothing has shipped.
- Registration requires email verification: open the emailed link (valid 24 h, single use), then confirm on the page that opens; this prevents email link scanners from consuming the link. Unverified accounts cannot log in. Google sign-in counts as verified. Admin can verify a user manually.

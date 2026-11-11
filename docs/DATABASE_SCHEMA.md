# ShopHub data relationships

```text
users 1 ??? * products
users 1 ??? * cart_items * ??? 1 products
users 1 ??? * orders 1 ??? * order_items
users 1 ??? * email_verifications
users 1 ??? * password_resets
users 1 ??? * social_accounts
```

User, product, cart, order, authentication, and verification relationships remain defined in `schema.sql`.

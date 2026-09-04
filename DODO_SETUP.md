# Dodo Payments setup for Arlong

The application is currently configured for `test_mode`. Do not switch to live mode until a complete test subscription, renewal/cancellation webhook, and customer-portal flow have passed.

## 1. Create the products

In the Dodo test-mode dashboard, open **Product Catalog → Products → Create product**.

Create **Arlong Pro Monthly** with:

- Product type: Subscription / recurring
- Price: INR 499
- Billing interval: Every 1 month
- Tax category: SaaS
- Tax inclusive: Enabled
- Purchasing power parity: Enabled, if available on the product form
- Description: 4,000 unified Arlong credits each month for Playground, REST API, and MCP

Copy the resulting product ID into `.env`:

```env
DODO_PAYMENTS_PRODUCT_ID_MONTHLY=pdt_...
```

Create **Arlong Pro Annual** separately with:

- Price: INR 5,000
- Billing interval: Every 1 year
- Description: 6,000 unified Arlong credits per monthly refill for Playground, REST API, and MCP
- All other settings identical to Monthly

Copy its ID:

```env
DODO_PAYMENTS_PRODUCT_ID_ANNUAL=pdt_...
```

Monthly and annual billing must be separate Dodo products.

Create or update **Arlong Founder** with:

- Price: INR 289
- Billing interval: Every 1 month
- Description: 2,500 unified Arlong credits each month for Playground, REST API, and MCP

Keep the existing `DODO_PAYMENTS_PRODUCT_ID_FOUNDER` environment name. Founder access is capped by the application at 100 active or pending seats.

Create or update the one-time prepaid-credit products to match the public dashboard:

| Credits | USD price |
| ---: | ---: |
| 100 | $1.49 |
| 200 | $2.69 |
| 300 | $3.79 |
| 600 | $6.99 |
| 1,500 | $15.99 |
| 3,000 | $29.99 |
| 6,000 | $54.99 |

Keep the existing `DODO_PAYMENTS_PRODUCT_ID_CREDITS_<amount>` environment names. The displayed price in Arlong does not change the amount charged by Dodo; the product prices must also be updated in the Dodo dashboard before deployment.

## 2. Enable regional currency

Open **Settings → Business** and enable **Adaptive Pricing / Adaptive Currency**. Dodo will determine the final country from the customer's billing details, convert into supported local currencies, and show the actual total at checkout.

Arlong only uses proxy country headers or browser language to show an initial price estimate. It does not trust an IP address for taxes or payment eligibility. Customers may use VPNs, and IP location is not reliable enough for a billing decision.

Start with the default adaptive-currency fee behavior, where the currency conversion fee is shown to the customer. Revisit fee-inclusive pricing after conversion data is available.

## 3. Configure the webhook

After the test deployment is reachable over HTTPS, create a webhook endpoint in Dodo:

```text
https://YOUR-DOMAIN/webhooks/dodo
```

Subscribe to at least:

- `subscription.active`
- `subscription.updated`
- `subscription.on_hold`
- `subscription.renewed`
- `subscription.cancelled`
- `subscription.failed`
- `subscription.expired`
- `payment.succeeded`
- `payment.failed`
- `refund.succeeded`
- `dispute.opened`

Copy the webhook signing secret—not the webhook ID—into:

```env
DODO_PAYMENTS_WEBHOOK_SECRET=whsec_...
```

Also set the deployed origin, without a trailing slash:

```env
PUBLIC_BASE_URL=https://YOUR-DOMAIN
```

## 4. Test checklist

1. Sign in with an Arlong account that has an email address.
2. Open `/premium` and start a monthly test checkout.
3. Complete the checkout using Dodo's test payment details.
4. Confirm `/billing/success` changes from activating to active after the signed webhook arrives.
5. Confirm Dashboard shows Pro, active status, and the next billing date.
6. Open **Manage subscription & invoices** and verify the hosted customer portal.
7. Cancel at period end and confirm the dashboard reflects the webhook state.
8. Test a failed renewal/on-hold event before enabling live mode.

## 5. Live cutover

Create equivalent products and a webhook in Dodo live mode. Product IDs and webhook secrets are environment-specific. Replace the product IDs and webhook secret with the live values, then set:

```env
DODO_PAYMENTS_ENVIRONMENT=live_mode
```

Rotate both API keys before launch because credentials shared in chat should be treated as exposed. Configure production secrets in the hosting provider rather than uploading the local `.env` file.

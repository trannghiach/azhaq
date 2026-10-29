# What a `watch` after the v1 → v2 deploy must report

Exactly these API changes, each tied to the script that calls the route (/main.js):

- **New route:** `POST /api/v2/export`, body fields `format`, `userId`.
- **New method on a known route:** `/api/orders/{id}` gains `DELETE` (it had `GET`).
- **New body field on a known route:** `PUT /api/profile` gains `role` (it had `name`, `email`).
- **Route gone from the bundle:** `/api/legacy/report`.

Nothing else is reported: the page title, `/` and `/main.js` stay. A second `watch` with no deploy in between reports no change.

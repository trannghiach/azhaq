# OWASP Juice Shop v20.3 (challenges and routes in the image's build/routes)

| Kind | Route | Expected verdict class | Source |
| --- | --- | --- | --- |
| positive | GET /rest/basket/{id} | reads another role's object | challenge "View Basket"; routes/basket.js serves any basket id to any signed-in user |
| positive | GET /api/Users | a signed-in user reads every user's records: listed (signed-in only, or sensitive fields) | challenge "Admin Section" data; models served by the generic API |
| positive | GET /rest/user/authentication-details | a signed-in user reads every user's session details: listed | routes/authenticatedUsers.js (password and totpSecret masked; deluxeToken not) |
| positive | PUT /api/BasketItems/{id} | writes another role's object (another user's basket item quantity) | challenge "Manipulate Basket" family; check with curl whether this instance accepts it |
| negative | GET /rest/user/whoami | own session only, not cross | routes/currentUser.js |
| negative | GET /api/Addresss/{id} for another user's address | not readable by the other user (answers 400/401/403 or empty) | earlier runs on this instance saw 400 "Malicious activity detected." for a cross read |

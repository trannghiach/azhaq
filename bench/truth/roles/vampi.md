# VAmPI (api_views/users.py and books.py in the image, vuln mode on)

| Kind | Route | Expected verdict class | Source |
| --- | --- | --- | --- |
| positive | GET /books/v1/{book_title} | reads another role's object | books.py get_by_title: `if vuln:  # Broken Object Level Authorization` |
| positive | PUT /users/v1/{username}/password | a write on another role's object accepted (2xx): writes another role's object, or listed with the 2xx answer and a note that the change cannot be read back | users.py update_password: `if vuln:  # Unauthorized update of password of another user` |
| positive | GET /users/v1/_debug | anyone reads sensitive fields (password) | users.py debug: returns every user with their password |
| negative | DELETE /users/v1/{username} as a non-admin | must not be a cross write (the server answers 401 "Only Admins may delete users!") | users.py delete_user |
| negative | GET /me for each user | own object, not cross | users.py me |

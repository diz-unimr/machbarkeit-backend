-- Create users table.
create table if not exists users
(
    id           integer primary key autoincrement,
    name         text not null,
    email        text not null unique,
    access_token text not null
);

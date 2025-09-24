create table if not exists users
(
    id                  integer primary key autoincrement,
    name                text not null,
    email               text not null unique,
    access_token        text not null
);

create table if not exists requests
(
    id                  uuid primary key,
    date                datetime with timezone not null,
    query               text not null,
    status              text not null,
    result_code         integer,
    result_body         text,
    result_duration     integer,
    user_id             integer,
    foreign key (user_id) references users(id)
);

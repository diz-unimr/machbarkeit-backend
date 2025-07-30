create table if not exists requests
(
    id                  uuid not null,
    date                datetime with timezone not null,
    query               text not null,
    status              text not null,
    result_code         integer,
    result_body         text,
    result_duration     integer,
    primary key (id)
);

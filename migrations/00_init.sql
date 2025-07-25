create table if not exists requests
(
    id              uuid not null,
    date            datetime with timezone not null,
    query           text not null,
    status          text not null,
    result          integer,
    duration        integer,
    error           text,
    primary key (id)
);

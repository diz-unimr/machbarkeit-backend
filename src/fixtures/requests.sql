insert into users (id, name, email, access_token)
values (1, 'Test', 'Test', 'eyJ...');
insert into requests (id, date, query, status, result_code, result_body, user_id)
values ('0b6e62ccf4e328ce', '2026-01-01 10:00:00', '{}', 'completed', '200', 42, 1),
       ('9a5a7d1c44484cfc', '2026-04-01 22:00:00', '{}', 'pending', '200', null, 1);
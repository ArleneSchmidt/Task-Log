create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null check (username ~ '^[A-Za-z0-9_.-]{3,30}$'),
  email text not null,
  created_at timestamptz not null default now()
);
create unique index if not exists profiles_username_lower on public.profiles (lower(username));
alter table public.profiles enable row level security;
drop policy if exists "own profile read" on public.profiles;
create policy "own profile read" on public.profiles for select using (auth.uid() = id);

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles(id, username, email)
  values (new.id, new.raw_user_meta_data->>'username', new.email);
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

create extension if not exists pgcrypto with schema extensions;
drop function if exists public.email_for_login(text);
create or replace function public.username_available(u text) returns boolean
language sql security definer set search_path = public stable as $$
  select not exists (select 1 from public.profiles where lower(username) = lower(u))
$$;
revoke all on function public.username_available(text) from public;
grant execute on function public.username_available(text) to anon, authenticated;

-- sign in with a username: returns the account's email only when the password is right,
-- so nobody can look up someone else's email. Locks a username for 15 minutes after 10 wrong tries.
create table if not exists public.login_attempts (
  username text primary key,
  fails int not null default 0,
  last_fail timestamptz
);
alter table public.login_attempts enable row level security;
create or replace function public.email_for_login(login text, pw text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare uid uuid; em text; h text; a public.login_attempts%rowtype;
begin
  select id, email into uid, em from public.profiles where lower(username) = lower(login) limit 1;
  if uid is null then return null; end if;
  select * into a from public.login_attempts where username = lower(login);
  if found and a.fails >= 10 and a.last_fail > now() - interval '15 minutes' then
    raise exception 'too_many_attempts';
  end if;
  select encrypted_password into h from auth.users where id = uid;
  if h is not null and h <> '' and h = extensions.crypt(pw, h) then
    delete from public.login_attempts where username = lower(login);
    return em;
  end if;
  insert into public.login_attempts(username, fails, last_fail) values (lower(login), 1, now())
  on conflict (username) do update set
    fails = case when public.login_attempts.last_fail < now() - interval '15 minutes' then 1 else public.login_attempts.fails + 1 end,
    last_fail = now();
  return null;
end $$;
revoke all on function public.email_for_login(text, text) from public;
grant execute on function public.email_for_login(text, text) to anon, authenticated;

create table if not exists public.user_data (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  updated_at bigint not null default 0
);
alter table public.user_data enable row level security;
drop policy if exists "own data select" on public.user_data;
drop policy if exists "own data insert" on public.user_data;
drop policy if exists "own data update" on public.user_data;
create policy "own data select" on public.user_data for select using (auth.uid() = user_id);
create policy "own data insert" on public.user_data for insert with check (auth.uid() = user_id);
create policy "own data update" on public.user_data for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
grant select, insert, update on public.user_data to authenticated;
grant select on public.profiles to authenticated;

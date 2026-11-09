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

create or replace function public.email_for_login(login text) returns text
language sql security definer set search_path = public stable as $$
  select email from public.profiles where lower(username) = lower(login) limit 1
$$;
create or replace function public.username_available(u text) returns boolean
language sql security definer set search_path = public stable as $$
  select not exists (select 1 from public.profiles where lower(username) = lower(u))
$$;
revoke all on function public.email_for_login(text) from public;
revoke all on function public.username_available(text) from public;
grant execute on function public.email_for_login(text) to anon, authenticated;
grant execute on function public.username_available(text) to anon, authenticated;

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

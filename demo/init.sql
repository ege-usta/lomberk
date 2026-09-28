CREATE TABLE public.users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    plan TEXT DEFAULT 'free',
    created_at TIMESTAMPTZ DEFAULT now()
);

INSERT INTO public.users (name, email, plan) VALUES
('Alice CEO', 'alice@pocketos.com', 'enterprise'),
('Bob CTO', 'bob@pocketos.com', 'enterprise'),
('Charlie Dev', 'charlie@pocketos.com', 'pro');

CREATE TABLE public.payments (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES public.users(id) ON DELETE CASCADE,
    amount DECIMAL(10,2) NOT NULL,
    status TEXT NOT NULL
);

INSERT INTO public.payments (user_id, amount, status) VALUES
(1, 1000.00, 'success'),
(2, 500.00, 'success');

-- Undogate needs two non-superuser roles: control (approvals) and agent (AI writes).
CREATE ROLE undogate_control LOGIN PASSWORD 'control-demo';
CREATE ROLE undogate_agent LOGIN PASSWORD 'agent-demo';

CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    message TEXT NOT NULL,
    sender_username VARCHAR(255) NOT NULL,
    receiver_username VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL
);

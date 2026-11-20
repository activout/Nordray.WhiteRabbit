-- rabbit admin audit lists an owner's newest events.
CREATE INDEX IX_SecurityEvents_UserId_Id ON SecurityEvents(UserId, Id);

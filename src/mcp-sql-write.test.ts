import { describe, expect, it } from "vitest";

import { mcpArgsHaveSqlWrite } from "./mcp-sql-write";

describe("mcpArgsHaveSqlWrite", () => {
  it.each([
    { sql: "DROP TABLE users" },
    { sql: "select 1; drop database prod" },
    { query: "DELETE FROM items WHERE id = 1" },
    { q: "insert into logs values (1)" },
    { q: "UPDATE users SET admin = true" },
    { q: "TRUNCATE orders" },
    { q: "ALTER TABLE users ADD COLUMN x int" },
    { q: "GRANT ALL ON db TO public" },
    { q: "CREATE OR REPLACE FUNCTION f() ..." },
    { nested: { statements: ["select 1", "drop table t"] } },
  ])("flags %o", (args) => {
    expect(mcpArgsHaveSqlWrite(args)).toBe(true);
  });

  it.each([
    { sql: "SELECT id, name FROM items LIMIT 10" },
    { query: "how to configure retries" },
    { owner: "acme", issue_number: 12 },
    { text: "updated the docs" },
    {},
  ])("does not flag %o", (args) => {
    expect(mcpArgsHaveSqlWrite(args)).toBe(false);
  });
});

-- Entity index: the noun layer of the wiki, used as a fourth retrieval
-- stream alongside FTS5, vector cosine, and page-link neighbours.
--
-- Entities come from the frontmatter `entities:` list that the
-- consolidator writes (extraction happens where an LLM already runs, so
-- the zero-LLM default path is untouched — an empty table simply
-- contributes nothing, exactly like the vector stream with no embedder).
-- Markdown stays the source of truth: `reindex` rebuilds both tables
-- from the files, same contract as `links`.
--
-- Query-time matching is lexical (exact + prefix over `name`), never an
-- LLM call.
--
-- Deliberately a plain noun table, not a triple store: `entities.id` is
-- the stable anchor a future temporal-triples table
-- (`subject_entity_id`, `predicate`, `object_entity_id`, `valid_from`,
-- `valid_to`, `source_page_id`) can reference. That P2 item stays
-- deferred — this builds only the foundation it would need, and no
-- graph database is involved either way.
CREATE TABLE entities (
    id            BLOB PRIMARY KEY,
    workspace_id  BLOB NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    project_id    BLOB NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- Lowercase-normalized surface form; uniqueness is per project so
    -- two projects can each have their own `postgres` entity.
    name          TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    UNIQUE (workspace_id, project_id, name)
);

CREATE TABLE entity_page_links (
    entity_id  BLOB NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    page_id    BLOB NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    PRIMARY KEY (entity_id, page_id)
);

-- Reverse lookup for the retrieval stream (page → entities) and for
-- replacing a page's entity set on rewrite.
CREATE INDEX idx_entity_page_links_page ON entity_page_links(page_id);
-- Prefix matching (`name LIKE 'postg%'`) rides this index.
CREATE INDEX idx_entities_name ON entities(workspace_id, project_id, name);

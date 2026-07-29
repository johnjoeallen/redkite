# Parent, BOM, and Ancestor

A Maven project can inherit dependency versions from more than one place: its parent POM (and that parent's own parent, and so on), and any BOMs it imports via `<scope>import</scope>` in `<dependencyManagement>`. RedKite needs to know what these ancestors actually manage — not just what the project's own POM says — to make correct decisions about coordinated release families like Jackson. See [Dependency Conflicts](../recommendations/dependency-conflicts.md) for why this matters.

## How RedKite resolves it

RedKite walks a module's parent chain and its imported BOMs recursively, following Maven's own real precedence rules:

- a module's own `dependencyManagement` (including its own BOM imports, in declaration order) wins over anything inherited from its parent
- a parent wins over a grandparent, and so on up the chain
- a `${property}` reference is resolved against whichever POM, walking from the start of the search, is the first one to actually declare that property

The walk is depth-bounded, so a misconfigured or accidentally circular parent chain can't cause it to loop forever.

## A known simplification

RedKite's resolver reads each POM's own `<properties>` block, but doesn't fully replicate Maven's property inheritance across that POM's *own* ancestors — so a property that a POM inherits from further up its chain, rather than declaring itself, isn't picked up. In practice this is uncommon for the property names that matter for family/BOM version resolution (they're almost always declared directly on the BOM or parent that owns them), but it's a real limitation worth knowing about if a resolution looks wrong for an unusual POM layout.

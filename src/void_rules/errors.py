class VoidRulesError(Exception):
    """Base exception for expected build failures."""


class CatalogError(VoidRulesError):
    """Catalog, recipe or overlay validation failed."""


class FetchError(VoidRulesError):
    """A registered remote source could not be fetched safely."""


class ParseError(VoidRulesError):
    """A source could not be parsed without ambiguity or loss."""


class BuildError(VoidRulesError):
    """A recipe failed assertions, conflict checks or output rendering."""


class CodecError(VoidRulesError):
    """A required MRS or DAT codec failed."""

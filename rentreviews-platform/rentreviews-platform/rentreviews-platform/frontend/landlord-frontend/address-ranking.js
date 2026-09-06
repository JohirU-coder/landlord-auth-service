// Pure ranking logic for the search page's address-suggestion dropdown,
// pulled out of search.html so it can be unit-tested directly (see
// test-address-ranking.js) instead of only being exercisable by driving a
// real browser. No DOM access here on purpose -- keep it that way so it
// stays trivially testable.
//
// Loaded via a plain <script> tag (see search.html), same pattern as
// config.js/session-guard.js -- also exports via module.exports when
// require()'d from Node (the test file) so the exact same code runs in
// both places instead of a hand-copied duplicate drifting out of sync.

function tokenize(text) {
    return (text || '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

// True if every token of `city` appears somewhere among the tokens the user
// actually typed -- e.g. typing "...paterson" matches a candidate whose
// city is "Paterson", but "Old Bridge Township" does NOT match just because
// the query also happens to contain other overlapping words.
function queryMentionsCity(queryTokens, city) {
    const cityTokens = tokenize(city);
    return cityTokens.length > 0 && cityTokens.every(t => queryTokens.includes(t));
}

// Common USPS street-suffix words, both spelled out and abbreviated. Used to
// make the suffix optional in queryMentionsStreet below rather than trying
// to maintain an alias table mapping every abbreviation to its full form --
// dropping the suffix requirement entirely handles "St" vs "Street" vs the
// word being left off completely, in either the query or the candidate's own
// data, all at once.
const STREET_SUFFIX_WORDS = new Set([
    'street', 'st', 'avenue', 'ave', 'av', 'road', 'rd', 'drive', 'dr',
    'lane', 'ln', 'court', 'ct', 'place', 'pl', 'boulevard', 'blvd',
    'circle', 'cir', 'square', 'sq', 'terrace', 'ter', 'parkway', 'pkwy',
    'highway', 'hwy', 'trail', 'trl', 'way', 'alley', 'aly', 'loop',
    'path', 'row', 'walk', 'close', 'crossing', 'xing', 'crescent', 'cres',
    'plaza', 'plz', 'point', 'pt', 'extension', 'ext'
]);

// Same idea as queryMentionsCity, but for the street itself -- `address` is
// just the street part (e.g. "18 Liberty Street" or "Liberty Street"). The
// house number and the suffix word are both stripped before comparing, so
// what's actually being matched is just the distinctive name ("liberty"),
// not incidental parts that vary in ways that don't change what street it
// is: a query with or without a house number, "St" vs "Street" vs no suffix
// word at all, all compare equal.
//
// This exists because a plain city match isn't enough on its own: searching
// "18 liberty street paterson" was ranking "18 Church Street, Paterson" and
// "51 East 18th Street, Paterson" above the actual "Liberty Street,
// Paterson" match, purely because those two happen to have a house number
// and Liberty Street's doesn't (a real data gap -- see geocode.js). Neither
// Church Street nor East 18th Street is the street the user typed at all;
// sharing a city should never outrank actually matching the street name.
// Dropping the suffix word specifically came from testing the abbreviated
// form of the same query ("18 Liberty St Paterson NJ"): comparing raw
// tokens required "street" to appear in the query, which "st" doesn't
// literally match, so the fix for the un-abbreviated case regressed on the
// abbreviated one until this was caught by a test.
function queryMentionsStreet(queryTokens, address) {
    const streetTokens = tokenize(address)
        .filter(t => !/^\d+$/.test(t)) // drop the house number, keep alphanumeric tokens like "18th"
        .filter(t => !STREET_SUFFIX_WORDS.has(t)); // suffix is optional, not required to match
    return streetTokens.length > 0 && streetTokens.every(t => queryTokens.includes(t));
}

// Lower score = shown first. `item` is one merged suggestion:
// { listed, address, city, hasHouseNumber, nearby }. `queryTokens` comes
// from tokenize(userTypedText).
//
// A weighted sum, not a series of if/else buckets -- each criterion must
// strictly dominate every criterion below it (each weight exceeds the sum
// of all lower ones), so e.g. house-number precision can only ever break a
// tie between two results that are ALREADY equally relevant on street/city,
// never override a street or city mismatch. An earlier version got this
// wrong twice, both caught by unit tests (see test-address-ranking.js):
// first by letting house-number form its own tier instead of just breaking
// ties, then by having no street-name signal at all so a city-only match
// with a house number could outrank the actual matching street without one.
//
// Priority order, highest weight first, matching the requested behavior
// (exact street+city, then exact street, then city-only, then everything
// else):
//  1. Already listed on RentReviews -- exactly what most searches want.
//  2. The candidate's own street name was actually typed by the user.
//  3. The candidate's own city was actually typed by the user.
//  4. Has a precise house-number-level match, not just a bare street.
//  5. Physically near the searcher's own location -- a tiebreaker bias for
//     otherwise-equal results, never a stand-in for relevance to what was
//     actually typed.
function rankSuggestion(item, queryTokens) {
    let score = 0;
    if (!item.listed) score += 16;
    if (!queryMentionsStreet(queryTokens, item.address)) score += 8;
    if (!queryMentionsCity(queryTokens, item.city)) score += 4;
    if (!item.hasHouseNumber) score += 2;
    if (!item.nearby) score += 1;
    return score;
}

const AddressRanking = { tokenize, queryMentionsCity, queryMentionsStreet, rankSuggestion };

if (typeof module !== 'undefined' && module.exports) {
    module.exports = AddressRanking;
}
if (typeof window !== 'undefined') {
    window.AddressRanking = AddressRanking;
}

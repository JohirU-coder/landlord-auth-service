// Tests for address-ranking.js, using Node's built-in test runner (no new
// dependency needed) -- run with: npm test  (or: node --test)
//
// Fixture shapes below are modeled directly on real API responses captured
// while diagnosing a live user-reported bug: searching "18 liberty street
// paterson" surfaced several wrong-city "18 Liberty Street" matches (Old
// Bridge Township NJ, Stamford CT, Middletown NY, ...) AND wrong-street
// same-city matches ("18 Church Street, Paterson", "51 East 18th Street,
// Paterson") ahead of the actually relevant "Liberty Street, Paterson, NJ"
// match -- which has no house number in ANY geocoder's data (confirmed
// live against Nominatim, Photon, AND Google), so it was either filtered
// out entirely or under-ranked below results that merely happened to share
// a city or a house number without matching what was actually typed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { tokenize, queryMentionsCity, queryMentionsStreet, rankSuggestion } = require('./address-ranking.js');

test('tokenize lowercases and splits on non-alphanumeric characters', () => {
    assert.deepEqual(tokenize('18 Liberty Street, Paterson, NJ'), ['18', 'liberty', 'street', 'paterson', 'nj']);
    assert.deepEqual(tokenize('  Extra   Spaces  '), ['extra', 'spaces']);
    assert.deepEqual(tokenize(''), []);
    assert.deepEqual(tokenize(undefined), []);
});

test('queryMentionsCity matches a single-word city mentioned anywhere in the query', () => {
    const tokens = tokenize('18 liberty street paterson');
    assert.equal(queryMentionsCity(tokens, 'Paterson'), true);
    assert.equal(queryMentionsCity(tokens, 'Stamford'), false);
});

test('queryMentionsCity requires every word of a multi-word city, not just one', () => {
    const tokens = tokenize('18 liberty street old bridge township');
    assert.equal(queryMentionsCity(tokens, 'Old Bridge Township'), true);
    // "township" alone appearing somewhere shouldn't false-match a
    // different multi-word city that happens to share one word.
    assert.equal(queryMentionsCity(tokens, 'Lakewood Township'), false);
});

test('queryMentionsCity is case-insensitive and ignores punctuation', () => {
    const tokens = tokenize('18 Liberty St, PATERSON, NJ 07522');
    assert.equal(queryMentionsCity(tokens, 'paterson'), true);
});

test('queryMentionsCity is false for an empty/missing city', () => {
    const tokens = tokenize('18 liberty street paterson');
    assert.equal(queryMentionsCity(tokens, ''), false);
    assert.equal(queryMentionsCity(tokens, undefined), false);
});

test('queryMentionsStreet matches the street name with the house number stripped from both sides', () => {
    const tokens = tokenize('18 liberty street paterson');
    assert.equal(queryMentionsStreet(tokens, '18 Liberty Street'), true);
    assert.equal(queryMentionsStreet(tokens, 'Liberty Street'), true, 'should match even when the candidate has no house number at all');
});

test('queryMentionsStreet matches regardless of which side abbreviates the suffix, or omits it entirely', () => {
    // Real regression caught by this exact test: an earlier version required
    // the literal token "street" to appear in the query, so typing the
    // abbreviated "St" (or leaving the suffix off entirely) failed to match
    // "Liberty Street" even though it's obviously the same street.
    assert.equal(queryMentionsStreet(tokenize('18 Liberty St Paterson NJ'), 'Liberty Street'), true, 'query abbreviates "Street" as "St"');
    assert.equal(queryMentionsStreet(tokenize('18 liberty paterson'), 'Liberty Street'), true, 'query drops the suffix word entirely');
    assert.equal(queryMentionsStreet(tokenize('18 liberty street paterson'), '18 Liberty St'), true, 'candidate\'s own data abbreviates "Street" as "St"');
});

test('queryMentionsStreet rejects a different street even if a house number happens to line up', () => {
    const tokens = tokenize('18 liberty street paterson');
    assert.equal(queryMentionsStreet(tokens, '18 Church Street'), false);
    assert.equal(queryMentionsStreet(tokens, '51 East 18th Street'), false, '"18" appearing inside "18th" is not the same token as the house number "18"');
});

test('rankSuggestion: the real bug, part 1 -- a correct-street match beats a house-numbered wrong-city match', () => {
    const queryTokens = tokenize('18 liberty street paterson');

    const correctStreetNoHouseNumber = { address: 'Liberty Street', city: 'Paterson', hasHouseNumber: false, nearby: true, listed: false };
    const wrongCityWithHouseNumber = { address: '18 Liberty Street', city: 'Old Bridge Township', hasHouseNumber: true, nearby: false, listed: false };
    const anotherWrongCity = { address: '18 Liberty Street', city: 'Stamford', hasHouseNumber: true, nearby: false, listed: false };

    const ranked = [wrongCityWithHouseNumber, anotherWrongCity, correctStreetNoHouseNumber]
        .sort((a, b) => rankSuggestion(a, queryTokens) - rankSuggestion(b, queryTokens));

    assert.equal(ranked[0], correctStreetNoHouseNumber, 'the Liberty St/Paterson match must rank first even without a house number');
});

test('rankSuggestion: the real bug, part 2 -- a correct-street match beats a wrong-street same-city match', () => {
    const queryTokens = tokenize('18 liberty street paterson');

    const correctStreetNoHouseNumber = { address: 'Liberty Street', city: 'Paterson', hasHouseNumber: false, nearby: true, listed: false };
    const sameCityWrongStreet1 = { address: '18 Church Street', city: 'Paterson', hasHouseNumber: true, nearby: true, listed: false };
    const sameCityWrongStreet2 = { address: '51 East 18th Street', city: 'Paterson', hasHouseNumber: true, nearby: true, listed: false };

    const ranked = [sameCityWrongStreet1, sameCityWrongStreet2, correctStreetNoHouseNumber]
        .sort((a, b) => rankSuggestion(a, queryTokens) - rankSuggestion(b, queryTokens));

    assert.equal(ranked[0], correctStreetNoHouseNumber, 'matching the actual street name must outrank merely sharing a city, even with a house number');
});

test('rankSuggestion: an already-listed property always outranks everything else', () => {
    const queryTokens = tokenize('18 liberty street paterson');
    const listedElsewhere = { address: '18 Liberty Street', city: 'Newburgh', hasHouseNumber: true, nearby: false, listed: true };
    const correctStreetNotListed = { address: 'Liberty Street', city: 'Paterson', hasHouseNumber: false, nearby: true, listed: false };

    const ranked = [correctStreetNotListed, listedElsewhere]
        .sort((a, b) => rankSuggestion(a, queryTokens) - rankSuggestion(b, queryTokens));

    assert.equal(ranked[0], listedElsewhere, 'a listed property outranks even a correct-street match, per the documented priority order');
});

test('rankSuggestion: house-number precision only breaks ties among equally street/city-relevant results', () => {
    const queryTokens = tokenize('liberty street paterson');
    const preciseMatch = { address: '18 Liberty Street', city: 'Paterson', hasHouseNumber: true, nearby: true, listed: false };
    const streetOnlyMatch = { address: 'Liberty Street', city: 'Paterson', hasHouseNumber: false, nearby: true, listed: false };

    const ranked = [streetOnlyMatch, preciseMatch]
        .sort((a, b) => rankSuggestion(a, queryTokens) - rankSuggestion(b, queryTokens));

    assert.equal(ranked[0], preciseMatch, 'between two equally-relevant results, the house-numbered one should win');
});

test('rankSuggestion: proximity to the searcher is only a final tiebreaker, never an override for street/city relevance', () => {
    const queryTokens = tokenize('18 liberty street paterson');
    // Physically close to the searcher, but the wrong street AND city.
    const nearbyWrongEverything = { address: '18 Main Street', city: 'Trenton', hasHouseNumber: true, nearby: true, listed: false };
    const farCorrectMatch = { address: 'Liberty Street', city: 'Paterson', hasHouseNumber: false, nearby: false, listed: false };

    const ranked = [nearbyWrongEverything, farCorrectMatch]
        .sort((a, b) => rankSuggestion(a, queryTokens) - rankSuggestion(b, queryTokens));

    assert.equal(ranked[0], farCorrectMatch, 'matching the typed street/city must outrank mere physical proximity to the searcher');
});

test('rankSuggestion: with no city or street mentioned, falls back to house-number then proximity (unchanged prior behavior)', () => {
    const queryTokens = tokenize('rentals near me'); // no street or city typed
    const nearHouseNumbered = { address: '104 Coral Street', city: 'Paterson', hasHouseNumber: true, nearby: true, listed: false };
    const farStreetOnly = { address: 'Coral Street', city: 'Miami', hasHouseNumber: false, nearby: false, listed: false };

    const ranked = [farStreetOnly, nearHouseNumbered]
        .sort((a, b) => rankSuggestion(a, queryTokens) - rankSuggestion(b, queryTokens));

    assert.equal(ranked[0], nearHouseNumbered);
});

test('rankSuggestion: full real-world scenario -- correct order for every candidate in the original bug report', () => {
    const queryTokens = tokenize('18 liberty street paterson');
    const items = [
        { address: '18 Church Street', city: 'Paterson', hasHouseNumber: true, nearby: true, listed: false },
        { address: '51 East 18th Street', city: 'Paterson', hasHouseNumber: true, nearby: true, listed: false },
        { address: '18 Liberty Street', city: 'Old Bridge Township', hasHouseNumber: true, nearby: true, listed: false },
        { address: '18 Liberty Street', city: 'Stamford', hasHouseNumber: true, nearby: false, listed: false },
        { address: '18 Liberty Street', city: 'Middletown', hasHouseNumber: true, nearby: false, listed: false },
        { address: 'Liberty Street', city: 'Paterson', hasHouseNumber: false, nearby: true, listed: false } // the actually-relevant match
    ];

    const ranked = [...items].sort((a, b) => rankSuggestion(a, queryTokens) - rankSuggestion(b, queryTokens));

    assert.equal(ranked[0].city, 'Paterson');
    assert.equal(ranked[0].address, 'Liberty Street', 'the exact street in the exact city must be the top suggestion');
});

test('rankSuggestion: same real-world scenario still resolves correctly when the query abbreviates "Street" as "St"', () => {
    const queryTokens = tokenize('18 Liberty St Paterson NJ');
    const items = [
        { address: '51 East 18th Street', city: 'Paterson', hasHouseNumber: true, nearby: true, listed: false },
        { address: '18th Avenue', city: 'Paterson', hasHouseNumber: false, nearby: true, listed: false },
        { address: '18 Liberty Street', city: 'Old Bridge Township', hasHouseNumber: true, nearby: true, listed: false },
        { address: 'Liberty Street', city: 'Paterson', hasHouseNumber: false, nearby: true, listed: false }
    ];

    const ranked = [...items].sort((a, b) => rankSuggestion(a, queryTokens) - rankSuggestion(b, queryTokens));

    assert.equal(ranked[0].address, 'Liberty Street', 'abbreviating "Street" as "St" must not push the correct match out of first place');
});

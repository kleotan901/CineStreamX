movie_list_response_schema_example = {
    "movies": [
        {
            "id": 933,
            "uuid": "41d3c001dccd4432a89f368073093878",
            "name": "The Dark Knight",
            "year": 2008,
            "time": 152,
            "imdb": 9,
            "description": "When a menace known as the Joker wreaks havoc and chaos on the "
            "people of Gotham, Batman, James Gordon and Harvey Dent must work "
            "together to put an end to the madness.",
        }
    ],
    "prev_page": "/movies/?page=1&per_page=1",
    "next_page": "r/movies/?page=3&per_page=1",
    "total_pages": 9933,
    "total_items": 9933,
}

movie_create_schema_example = {
    "name": "The Dark Knight",
    "year": 2008,
    "time": 152,
    "imdb": 9,
    "votes": 3000000,
    "meta_score": 84,
    "gross": 1006000000,
    "description": "When a menace known as the Joker wreaks havoc and chaos on the "
    "people of Gotham, Batman, James Gordon and Harvey Dent must work "
    "together to put an end to the madness.",
    "price": 104.00,
    "certification_id": 1,
    "genres": ["Crime", "Adventure"],
    "stars": ["John Doe", "Jane Doe"],
    "directors": ["Christopher Nolan"],
}

certification_schema_example = {"id": 1, "name": "PG-13"}

genre_schema_example = {"id": 1, "name": "Crime"}

star_schema_example = {"id": 1, "name": "Christian Bale"}

director_schema_example = {"id": 1, "name": "Christopher Nolan"}

comment_schema_example = {"user_id": 1, "comment": "text of comment"}

movie_detail_schema_example = {
    "id": 933,
    "uuid": "41d3c001dccd4432a89f368073093878",
    "name": "The Dark Knight",
    "year": 2008,
    "time": 152,
    "imdb": 9,
    "votes": 3000000,
    "meta_score": 84,
    "gross": 1006000000,
    "description": "When a menace known as the Joker wreaks havoc and chaos on the "
    "people of Gotham, Batman, James Gordon and Harvey Dent must work "
    "together to put an end to the madness.",
    "price": 104.00,
    "genres": [genre_schema_example],
    "stars": [star_schema_example],
    "directors": [director_schema_example],
}

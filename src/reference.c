#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>

#include "reference.h"
#include "index.h"

#define REFERENCES_HEADER "## References"

static int parse_controlled_reference(
    const char* text,
    document_reference* reference,
    size_t* identifier_length)
{
    size_t i = 0;
    size_t root_end;

    if (text == NULL ||
        reference == NULL) {

        return 0;
    }

    memset(
        reference,
        0,
        sizeof(*reference)
    );

    while (i < 8) {

        if (!isdigit(
            (unsigned char)text[i])) {

            return 0;
        }

        ++i;
    }

    if (text[i] != '.') {
        return 0;
    }

    ++i;

    if (!isdigit(
        (unsigned char)text[i])) {

        return 0;
    }

    while (isdigit(
        (unsigned char)text[i])) {

        ++i;
    }

    root_end = i;

    if (root_end >=
        REFERENCE_ROOT_SIZE) {

        return 0;
    }

    memcpy(
        reference->root_document_id,
        text,
        root_end
    );

    reference
        ->root_document_id[
            root_end
        ] = '\0';

    /*
     * Explicit revision:
     *
     * YYYYMMDD.#.R#
     */
    if (text[i] == '.' &&
        text[i + 1] == 'R') {

        size_t revision_end;

        i += 2;

        if (!isdigit(
            (unsigned char)text[i])) {

            return 0;
        }

        while (isdigit(
            (unsigned char)text[i])) {

            ++i;
        }

        revision_end = i;

        if (revision_end >=
            REFERENCE_REVISION_SIZE) {

            return 0;
        }

        memcpy(
            reference->revision_id,
            text,
            revision_end
        );

        reference
            ->revision_id[
                revision_end
            ] = '\0';

        reference->explicit_revision = 1;
    }

    if (text[i] != '\0' &&
        text[i] != '\r' &&
        text[i] != '\n' &&
        text[i] != ' ' &&
        text[i] != '\t') {

        return 0;
    }

    if (identifier_length != NULL) {
        *identifier_length = i;
    }

    return 1;
}

static int reference_duplicate(
    const reference_list* references,
    const document_reference* candidate)
{
    size_t i;

    if (references == NULL ||
        candidate == NULL) {

        return 0;
    }

    for (i = 0;
        i < references->count;
        ++i) {

        const document_reference* existing =
            &references->items[i];

        if (candidate->explicit_revision !=
            existing->explicit_revision) {

            continue;
        }

        if (strcmp(
            candidate->root_document_id,
            existing->root_document_id) != 0) {

            continue;
        }

        if (candidate->explicit_revision) {

            if (strcmp(
                candidate->revision_id,
                existing->revision_id) == 0) {

                return 1;
            }
        }
        else {
            return 1;
        }
    }

    return 0;
}

reference_result reference_read_document(
    const char* path,
    reference_list* references)
{
    FILE* fp = NULL;

    char line[1024];

    int in_references = 0;

    if (path == NULL ||
        references == NULL) {

        return REFERENCE_ERR_ARGUMENT;
    }

    memset(
        references,
        0,
        sizeof(*references)
    );

    if (fopen_s(
        &fp,
        path,
        "rb") != 0 ||
        fp == NULL) {

        return REFERENCE_ERR_OPEN;
    }

    while (fgets(
        line,
        sizeof(line),
        fp) != NULL) {

        char* current = line;

        if (!in_references) {

            if (strncmp(
                current,
                REFERENCES_HEADER,
                strlen(REFERENCES_HEADER)) == 0) {

                in_references = 1;
            }

            continue;
        }

        if (strncmp(
            current,
            "## ",
            3) == 0) {

            break;
        }

        if (strncmp(
            current,
            "- ",
            2) != 0) {

            continue;
        }

        current += 2;

        /*
         * Non-controlled textual references
         * are ignored by this lookup path.
         */
        if (!isdigit(
            (unsigned char)current[0])) {

            continue;
        }

        if (references->count >=
            REFERENCE_MAX_COUNT) {

            fclose(fp);
            return REFERENCE_ERR_TOO_MANY;
        }

        if (!parse_controlled_reference(
            current,
            &references
            ->items[
                references->count
            ],
            NULL)) {

            fclose(fp);
            return REFERENCE_ERR_MALFORMED;
        }

        if (reference_duplicate(
            references,
            &references
            ->items[
                references->count
            ])) {

            fclose(fp);
            return REFERENCE_ERR_DUPLICATE;
        }

        ++references->count;
    }

    if (ferror(fp)) {
        fclose(fp);
        return REFERENCE_ERR_READ;
    }

    fclose(fp);

    return REFERENCE_OK;
}

reference_result reference_update_document(
    const char* path,
    const char* index_path,
    reference_update_summary* summary)
{
    FILE* input = NULL;
    FILE* output = NULL;

    char line[2048];
    char temp_path[MAX_PATH];

    int in_references = 0;

    if (path == NULL ||
        index_path == NULL ||
        summary == NULL) {

        return REFERENCE_ERR_ARGUMENT;
    }

    memset(
        summary,
        0,
        sizeof(*summary)
    );

    if (index_get_state(index_path) !=
        INDEX_EXISTS) {

        return REFERENCE_ERR_NOT_FOUND;
    }

    if (snprintf(
        temp_path,
        sizeof(temp_path),
        "%s.references.tmp",
        path
    ) <= 0) {

        return REFERENCE_ERR_WRITE;
    }

    DeleteFileA(temp_path);

    if (fopen_s(
        &input,
        path,
        "rb") != 0 ||
        input == NULL) {

        return REFERENCE_ERR_OPEN;
    }

    if (fopen_s(
        &output,
        temp_path,
        "wb") != 0 ||
        output == NULL) {

        fclose(input);
        return REFERENCE_ERR_WRITE;
    }

    while (fgets(
        line,
        sizeof(line),
        input) != NULL) {

        char* current = line;

        if (!in_references) {

            if (strncmp(
                current,
                REFERENCES_HEADER,
                strlen(REFERENCES_HEADER)) == 0) {

                in_references = 1;
            }

            if (fputs(
                line,
                output) == EOF) {

                fclose(input);
                fclose(output);
                DeleteFileA(temp_path);

                return REFERENCE_ERR_WRITE;
            }

            continue;
        }

        if (strncmp(
            current,
            "## ",
            3) == 0) {

            in_references = 0;

            if (fputs(
                line,
                output) == EOF) {

                fclose(input);
                fclose(output);
                DeleteFileA(temp_path);

                return REFERENCE_ERR_WRITE;
            }

            continue;
        }

        if (strncmp(
            current,
            "- ",
            2) != 0 ||
            !isdigit(
                (unsigned char)current[2])) {

            if (fputs(
                line,
                output) == EOF) {

                fclose(input);
                fclose(output);
                DeleteFileA(temp_path);

                return REFERENCE_ERR_WRITE;
            }

            continue;
        }

        {
            document_reference reference;
            size_t identifier_length;

            char* reference_text =
                current + 2;

            if (!parse_controlled_reference(
                reference_text,
                &reference,
                &identifier_length)) {

                fclose(input);
                fclose(output);
                DeleteFileA(temp_path);

                return REFERENCE_ERR_MALFORMED;
            }

            ++summary->checked;

            /*
             * Explicit revision:
             * verify exactly and preserve.
             */
            if (reference.explicit_revision) {

                index_match_result match;

                match = index_find_revision(
                    index_path,
                    reference.root_document_id,
                    reference.revision_id
                );

                if (match != INDEX_MATCH_ONE) {

                    fclose(input);
                    fclose(output);
                    DeleteFileA(temp_path);

                    return REFERENCE_ERR_EXPLICIT_REVISION;
                }

                ++summary->explicit_verified;

                if (fputs(
                    line,
                    output) == EOF) {

                    fclose(input);
                    fclose(output);
                    DeleteFileA(temp_path);

                    return REFERENCE_ERR_WRITE;
                }

                continue;
            }

            /*
             * Root-only reference:
             * resolve latest APPROVED revision.
             */
            {
                index_revision_resolution resolution;

                index_resolve_result resolved;

                resolved =
                    index_resolve_latest_approved(
                        index_path,
                        reference.root_document_id,
                        &resolution
                    );

                if (resolved ==
                    INDEX_RESOLVE_NONE) {

                    fclose(input);
                    fclose(output);
                    DeleteFileA(temp_path);

                    return
                        REFERENCE_ERR_NO_APPROVED_REVISION;
                }

                if (resolved !=
                    INDEX_RESOLVE_FOUND) {

                    fclose(input);
                    fclose(output);
                    DeleteFileA(temp_path);

                    return REFERENCE_ERR_NOT_FOUND;
                }

                /*
                 * Preserve everything after
                 * the original root ID exactly.
                 */
                if (fprintf(
                    output,
                    "- %s%s",
                    resolution.revision_id,
                    reference_text +
                    identifier_length) < 0) {

                    fclose(input);
                    fclose(output);
                    DeleteFileA(temp_path);

                    return REFERENCE_ERR_WRITE;
                }

                ++summary->updated;
            }
        }
    }

    if (ferror(input)) {

        fclose(input);
        fclose(output);
        DeleteFileA(temp_path);

        return REFERENCE_ERR_READ;
    }

    fclose(input);

    if (fflush(output) != 0) {

        fclose(output);
        DeleteFileA(temp_path);

        return REFERENCE_ERR_WRITE;
    }

    if (fclose(output) != 0) {

        DeleteFileA(temp_path);

        return REFERENCE_ERR_WRITE;
    }

    /*
     * Replace source only after the entire
     * prepared document has succeeded.
     */
    if (!MoveFileExA(
        temp_path,
        path,
        MOVEFILE_REPLACE_EXISTING |
        MOVEFILE_WRITE_THROUGH)) {

        DeleteFileA(temp_path);

        return REFERENCE_ERR_REPLACE;
    }

    return REFERENCE_OK;
}

const char* reference_result_string(
    reference_result result)
{
    switch (result) {

    case REFERENCE_OK:
        return "PASS";

    case REFERENCE_ERR_ARGUMENT:
        return "FAIL_REFERENCE_ARGUMENT";

    case REFERENCE_ERR_OPEN:
        return "FAIL_REFERENCE_OPEN";

    case REFERENCE_ERR_READ:
        return "FAIL_REFERENCE_READ";

    case REFERENCE_ERR_WRITE:
        return "FAIL_REFERENCE_WRITE";

    case REFERENCE_ERR_REPLACE:
        return "FAIL_REFERENCE_REPLACE";

    case REFERENCE_ERR_TOO_MANY:
        return "FAIL_REFERENCE_LIMIT";

    case REFERENCE_ERR_DUPLICATE:
        return "FAIL_REFERENCE_DUPLICATE";

    case REFERENCE_ERR_MALFORMED:
        return "FAIL_REFERENCE_MALFORMED";

    case REFERENCE_ERR_NOT_FOUND:
        return "FAIL_REFERENCE_NOT_FOUND";

    case REFERENCE_ERR_NO_APPROVED_REVISION:
        return "FAIL_REFERENCE_NO_APPROVED_REVISION";

    case REFERENCE_ERR_EXPLICIT_REVISION:
        return "FAIL_REFERENCE_EXPLICIT_REVISION";

    default:
        return "FAIL_REFERENCE_UNKNOWN";
    }
}
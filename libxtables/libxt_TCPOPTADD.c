#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include "xt_TCPOPTADD.h"

enum {
    O_TCPOPT_REPLACE,
    O_TCPOPT_SHRINK,
    O_TCPOPT_HEX,
};

static void TCPOPTADD_help(void)
{
    printf(
"TCPOPTADD target options:\n"
"  --rpl                       Replace all tcp option\n"
"  --shrink                    Shrink tcp option\n"
"  --hex str                   Set tcp option hex str, eg.\"|aabbcc001122|\"\n"
);
}

static const struct xt_option_entry TCPOPTADD_opts[] = {
    {.name = "rpl", .id = O_TCPOPT_REPLACE, .type = XTTYPE_NONE, },
    {.name = "shrink", .id = O_TCPOPT_SHRINK, .type = XTTYPE_NONE, },
    {.name = "hex", .id = O_TCPOPT_HEX, .type = XTTYPE_STRING, },
    XTOPT_TABLEEND,
};

static int parse_hex_string(const char *s, struct xt_tcpoptadd_info *info)
{
    int i=0, slen, sindex=0, schar;
    short hex_f = 0, literal_f = 0;
    char hextmp[3];

    slen = strlen(s);

    if (slen == 0) {
        xtables_error(PARAMETER_PROBLEM,
                "STRING must contain at least one char");
    }

    while (i < slen) {
        if (sindex >= 40)
            xtables_error(PARAMETER_PROBLEM,
                    "STRING too long \"%s\"", s);
        if (s[i] == '\\' && !hex_f) {
            literal_f = 1;
        } else if (s[i] == '\\') {
            xtables_error(PARAMETER_PROBLEM,
                    "Cannot include literals in hex data");
        } else if (s[i] == '|') {
            if (hex_f)
                hex_f = 0;
            else {
                hex_f = 1;
                /* get past any initial whitespace just after the '|' */
                while (s[i+1] == ' ')
                    i++;
            }
            if (i+1 >= slen)
                break;
            else
                i++;  /* advance to the next character */
        }

        if (literal_f) {
            if (i+1 >= slen) {
                xtables_error(PARAMETER_PROBLEM,
                        "Bad literal placement at end of string");
            }
            info->opt[sindex] = s[i+1];
            i += 2;  /* skip over literal char */
            literal_f = 0;
        } else if (hex_f) {
            if (i+1 >= slen) {
                xtables_error(PARAMETER_PROBLEM,
                        "Odd number of hex digits");
            }
            if (i+2 >= slen) {
                /* must end with a "|" */
                xtables_error(PARAMETER_PROBLEM, "Invalid hex block");
            }
            if (! isxdigit(s[i])) /* check for valid hex char */
                xtables_error(PARAMETER_PROBLEM, "Invalid hex char '%c'", s[i]);
            if (! isxdigit(s[i+1])) /* check for valid hex char */
                xtables_error(PARAMETER_PROBLEM, "Invalid hex char '%c'", s[i+1]);
            hextmp[0] = s[i];
            hextmp[1] = s[i+1];
            hextmp[2] = '\0';
            if (! sscanf(hextmp, "%x", &schar))
                xtables_error(PARAMETER_PROBLEM,
                        "Invalid hex char `%c'", s[i]);
            info->opt[sindex] = (char) schar;
            if (s[i+2] == ' ')
                i += 3;  /* spaces included in the hex block */
            else
                i += 2;
        } else {  /* the char is not part of hex data, so just copy */
            info->opt[sindex] = s[i];
            i++;
        }
        sindex++;
    }
    info->opt_len = sindex;
}

static void TCPOPTADD_parse(struct xt_option_call *cb)
{
    struct xt_tcpoptadd_info *info = cb->data;

    xtables_option_parse(cb);
    switch (cb->entry->id) {
    case O_TCPOPT_REPLACE:
        info->replace = 1;
        break;
    case O_TCPOPT_SHRINK:
        info->shrink = 1;
        break;
    case O_TCPOPT_HEX:
        parse_hex_string(cb->arg, info);
        break;
    }
}

static void TCPOPTADD_check(struct xt_fcheck_call *cb)
{
}

static void TCPOPTADD_print(const void *ip, const struct xt_entry_target *target,
                           int numeric)
{
    int i;
    const struct xt_tcpoptadd_info *info =
        (const struct xt_tcpoptadd_info *)target->data;

    printf(" TCPOPTADD ");
    if (info->replace)
        printf("rpl ");
    if (info->shrink)
        printf("shrink ");
    if (info->opt_len) {
        printf("hex ");
        for (i = 0; i < info->opt_len; i++) {
            printf("%02x", info->opt[i]);
        }
    }
}

static void TCPOPTADD_save(const void *ip, const struct xt_entry_target *target)
{
    int i;
    const struct xt_tcpoptadd_info *info =
        (const struct xt_tcpoptadd_info *)target->data;

    if (info->replace)
        printf(" --rpl");
    if (info->shrink)
        printf(" --shrink");
    if (info->opt_len) {
        printf(" --hex");
        printf(" \"|");
        for (i = 0; i < info->opt_len; i++) {
            printf("%02x", info->opt[i]);
        }
        printf("|\"");
    }
}

static struct xtables_target tcpoptadd_tg_reg = {
    .family        = NFPROTO_UNSPEC,
    .name          = "TCPOPTADD",
    .version       = XTABLES_VERSION,
    .revision      = 0,
    .size          = XT_ALIGN(sizeof(struct xt_tcpoptadd_info)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_tcpoptadd_info)),
    .help          = TCPOPTADD_help,
    .print         = TCPOPTADD_print,
    .save          = TCPOPTADD_save,
    .x6_parse      = TCPOPTADD_parse,
    .x6_fcheck     = TCPOPTADD_check,
    .x6_options    = TCPOPTADD_opts,
};

void _init(void)
{
    xtables_register_target(&tcpoptadd_tg_reg);
}

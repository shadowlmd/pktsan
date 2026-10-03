/*
 * pktsan (PKT Sanitizer) - truncate too long toUserName, fromUserName and
 * subject fields of packed messages in FTS-0001 packets (*.pkt).
 *
 * Packed message (FTS-0001):
 *   messageType 2 bytes, origNode, destNode, origNet, destNet, attribute,
 *   cost 2 bytes each, DateTime 20 bytes, toUserName{36}, fromUserName{36},
 *   subject{72}, text{unbounded}. {n} is a null terminated string of up to
 *   n bytes including the null.
 *
 * Only these three strings are changed; everything else, including data
 * that can not be parsed as packed messages, is kept byte for byte. The
 * strings are truncated in every message whose header can be read, even if
 * the rest of the message is cut off by the end of the file.
 * A modified message is logged with the area from the AREA line, the
 * strings as written and the addresses from the message header.
 * A packet is rewritten only when something has to be truncated: the new
 * packet is written to name.tr$, copied over name.pkt and deleted, so the
 * directory entry of name.pkt stays. The case of the extension is kept:
 * NAME.PKT <-> NAME.TR#. A name.tr$ left by an interrupted run is renamed
 * to name.pkt if there is none, otherwise it is compared with name.pkt
 * processed again (see RestoreTmp()).
 * A packet that needs changes but can't be changed (no memory, name.tr$
 * exists or can't be written) is renamed to name.bad, or to an unused
 * XXXXXXXX.bad, so that the tosser does not get it.
 *
 * Build: gcc -O2 -o pktsan pktsan.c
 *        (MinGW: gcc -O2 -static-libgcc -o pktsan.exe pktsan.c)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <utime.h>
#include <unistd.h>

/*
 * MinGW, Watcom, Borland, DJGPP and EMX have stricmp(), Unix strcasecmp().
 * DIRSEP is the default directory separator, DRIVES says if "c:" exists.
 */
#if defined(__unix__) || defined(__APPLE__)
#include <strings.h>
#define stricmp strcasecmp
#define DIRSEP  '/'
#define DRIVES  0
#else
#define DIRSEP  '\\'
#define DRIVES  1
#endif

#define PROGNAME    "pktsan"
#define VERSION     "1.0"
#define CONFIGNAME  "pktsan.cfg"

#define PKT_HDR_SIZE 58   /* packet header */
#define MSG_HDR_SIZE 34   /* messageType .. DateTime */
#define LINE_SIZE    256  /* start of the text kept for the AREA line */

#define LOG_ERR   0   /* a packet or a file is skipped */
#define LOG_WARN  1   /* a problem pktsan fixed or worked around */
#define LOG_INFO  2   /* processed packets */

static FILE * LogFh    = NULL;
static int    LogLevel = LOG_INFO;

static const char * FieldName[3] = { "toUserName", "fromUserName", "subject" };
static const long   FieldSize[3] = { 36, 36, 72 };

typedef struct
{
    long at;       /* offset of the first byte cut off */
    long cut;      /* number of bytes cut off */
} Trunc;

/* A message being scanned, for the log */
typedef struct
{
    unsigned char Hdr[MSG_HDR_SIZE];
    char Str[3][72];         /* toUserName, fromUserName, subject, truncated */
    long Len[3];             /* original length if truncated, else 0 */
    char Text[LINE_SIZE];    /* start of the text */
} Msg;

/* The names for one file in a directory, in one block (see NewFiles()) */
typedef struct
{
    char * Pkt;    /* dir/name.pkt */
    char * Tmp;    /* dir/name.tr$ */
    char * Bad;    /* dir/name.bad */
    char * New;    /* dir/XXXXXXXX.ext, an unused name */
    char * Name;   /* Pkt with the packet addresses, for the log */
    char * Why;    /* why the packet goes to .bad, for the log */
} Files;

/* The result of ScanPacket() */
typedef struct
{
    unsigned char Hdr[PKT_HDR_SIZE]; /* packet header, if Size allows */
    long    Size;     /* file size */
    long    Tail;     /* offset after the last complete message */
    int     B0, B1;   /* first two bytes at Tail, EOF if none */
    long    Msgs;     /* messages, a cut off one included */
    long    Mod;      /* messages with truncated strings */
    long    OutLen;   /* file size after truncation */
    Trunc * Tr;       /* truncations in file order (allocated) */
    long    TrCount;
    int     NoMem;    /* no memory for more truncations, scan stopped */
} Scan;

/* ------------------------------------------------------------------ */

static void Log(int Level, const char * Fmt, ...)
{
    static const char * Names[] = { "err", "warn", "info" };
    va_list ap;
    time_t t;
    struct tm * tm;
    char Stamp[32] = "0000-00-00 00:00:00";
    FILE * fh;
    int Err = errno; /* kept for the caller's error message */

    if(Level > LogLevel)
    {
        return;
    }

    fh = (LogFh != NULL) ? LogFh : stdout;
    t  = time(NULL);
    tm = localtime(&t);

    if(tm != NULL)
    {
        strftime(Stamp, sizeof(Stamp), "%Y-%m-%d %H:%M:%S", tm);
    }

    fprintf(fh, "%s [%s] ", Stamp, Names[Level]);
    va_start(ap, Fmt);
    vfprintf(fh, Fmt, ap);
    va_end(ap);
    fputc('\n', fh);
    fflush(fh);
    errno = Err;
}

/*
 * Allocates Size bytes. Without memory even for file names nothing can be
 * done, so the program stops.
 */
static void * AllocOrDie(size_t Size)
{
    void * p = malloc(Size);

    if(p == NULL)
    {
        Log(LOG_ERR, "not enough memory, stopped");
        exit(1);
    }

    return p;
}

static char * StrDupOrDie(const char * s)
{
    return strcpy((char *)AllocOrDie(strlen(s) + 1), s);
}

/*
 * Logs Value of What that the code does not handle (a bug), handled as the
 * known value As. Keeps errno.
 */
static void Unexpected(const char * What, int Value, int As)
{
    Log(LOG_ERR, "bug found, please report it: unexpected %s %d, handled "
        "as %d", What, Value, As);
}

/*
 * Grows array P of N elements of Size bytes by one element. Returns NULL,
 * keeping P, if the new size does not fit in size_t or there is no memory.
 */
static void * Grow(void * P, long N, size_t Size)
{
    if((unsigned long)N >= (size_t)-1 / Size)
    {
        return NULL;
    }

    return realloc(P, (size_t)(N + 1) * Size);
}

/*
 * "name.pkt" <-> "name.tr$", "NAME.PKT" <-> "NAME.TR#", in place: the
 * extension of a packet <-> of its temporary file, letter by letter in the
 * same case
 */
static void SwapExt(char * Name)
{
    /* each letter and its pair two places away: p <-> t, P <-> T, ... */
    static const char * Swap[3] = { "pPtT", "kKrR", "tT$#" };
    char * e = Name + strlen(Name) - 3;
    int i;

    for(i = 0; i < 3; i++)
    {
        const char * q = strchr(Swap[i], e[i]);

        if(q != NULL)
        {
            e[i] = Swap[i][(q - Swap[i]) ^ 2];
        }
    }
}

/* A directory separator: '/', and DIRSEP ('\\' except on Unix) */
static int IsSep(char c)
{
    return c == '/' || c == DIRSEP;
}

/*
 * Out = Dir + separator + Name; the separator follows the style of Dir.
 * Out has room for strlen(Dir) + strlen(Name) + 2 bytes.
 */
static void JoinPath(char * Out, const char * Dir, const char * Name)
{
    size_t l = strlen(Dir);
    char Sep = (strchr(Dir, '/') != NULL && strchr(Dir, DIRSEP) == NULL) ?
               '/' : DIRSEP;

    strcpy(Out, Dir);

    if(l > 0 && !IsSep(Dir[l - 1]) && !(DRIVES && Dir[l - 1] == ':'))
    {
        Out[l++] = Sep;
    }

    strcpy(Out + l, Name);
}

static int HasExt(const char * Name, const char * Ext)
{
    size_t l = strlen(Name);

    return l >= 4 && stricmp(Name + l - 4, Ext) == 0;
}

/* ------------------------------------------------------------------ */
/* Configuration                                                      */

/* The file name of Path without the directory */
static const char * BaseName(const char * Path)
{
    const char * p = Path + strlen(Path);

    while(p > Path && !IsSep(p[-1]) && !(DRIVES && p[-1] == ':'))
    {
        p--;
    }

    return p;
}

/*
 * Out = Name in the directory of Path: "dir/file" + Name -> "dir/Name".
 * Out has room for strlen(Path) + strlen(Name) + 1 bytes.
 */
static void SameDir(char * Out, const char * Path, const char * Name)
{
    size_t l = (size_t)(BaseName(Path) - Path);

    memcpy(Out, Path, l);
    strcpy(Out + l, Name);
}

static int IsAbsolute(const char * Path)
{
    return IsSep(Path[0]) || (DRIVES && Path[0] != '\0' && Path[1] == ':');
}

static char * Trim(char * s)
{
    char * e;

    s += strspn(s, " \t");
    e  = s + strlen(s);

    while(e > s && strchr(" \t\r\n", e[-1]) != NULL)
    {
        *--e = '\0';
    }

    return s;
}

/*
 * Returns 0 on success. A missing config is fine unless Required. LogFile
 * is set (allocated) if the config has it.
 */
static int ReadConfig(const char * Path, int Required, char ** LogFile)
{
    FILE * fh;
    char Line[1024];
    int LineNo = 0;
    int Rc = 0;

    fh = fopen(Path, "r");

    if(fh == NULL)
    {
        if(Required)
        {
            fprintf(stderr, PROGNAME ": can't open config '%s': %s\n", Path,
                    strerror(errno));
            return 1;
        }

        return 0;
    }

    while(fgets(Line, sizeof(Line), fh) != NULL)
    {
        char * Key;
        char * Val;
        size_t l;

        LineNo++;
        Key = Trim(Line);

        if(*Key == '\0' || *Key == '#' || *Key == ';')
        {
            continue;
        }

        Val = Key + strcspn(Key, " \t");

        if(*Val != '\0')
        {
            *Val++ = '\0';
        }

        Val = Trim(Val);
        l   = strlen(Val);

        if(l >= 2 && Val[0] == '"' && Val[l - 1] == '"')
        {
            Val[l - 1] = '\0';
            Val++;
        }

        if(stricmp(Key, "LogFile") == 0 && *Val != '\0')
        {
            /* a relative log path is relative to the config */
            free(*LogFile);

            if(IsAbsolute(Val))
            {
                *LogFile = StrDupOrDie(Val);
            }
            else
            {
                *LogFile = (char *)AllocOrDie(strlen(Path) + strlen(Val) + 1);
                SameDir(*LogFile, Path, Val);
            }
        }
        else if(stricmp(Key, "LogLevel") == 0 && stricmp(Val, "info") == 0)
        {
            LogLevel = LOG_INFO;
        }
        else if(stricmp(Key, "LogLevel") == 0 && stricmp(Val, "warn") == 0)
        {
            LogLevel = LOG_WARN;
        }
        else
        {
            fprintf(stderr, PROGNAME ": %s(%d): bad line '%s%s%s'\n", Path,
                    LineNo, Key, *Val ? " " : "", Val);
            Rc = 1;
        }
    }

    fclose(fh);
    return Rc;
}

/* ------------------------------------------------------------------ */
/* Packet processing                                                  */

static unsigned Word(const unsigned char * p)
{
    return p[0] | ((unsigned)p[1] << 8);
}

/* Signed 16-bit number: a part of an address (-1 in address requests) */
static int SWord(const unsigned char * p)
{
    unsigned w = Word(p);

    return (w & 0x8000) ? -(int)(~w & 0x7FFF) - 1 : (int)w;
}

/* zone:net/node.point, without "zone:" if 0 and without ".point" if 0 */
static char * FormatAddr(char * p, int Zone, int Net, int Node, int Point)
{
    if(Zone != 0)
    {
        p += sprintf(p, "%d:", Zone);
    }

    p += sprintf(p, "%d/%d", Net, Node);

    if(Point != 0)
    {
        p += sprintf(p, ".%d", Point);
    }

    return p;
}

/*
 * Out = Path + " (orig -> dest)" from packet header Hdr: type 2+ (FSC-0039,
 * FSC-0048), type 2.2 (FSC-0045) or type 2 (FTS-0001, zones from QMail).
 * An address takes up to 27 characters, Out has room for strlen(Path) + 64.
 */
static void PktName(char * Out, const char * Path, const unsigned char * Hdr)
{
    int      OZone = SWord(Hdr + 34), DZone = SWord(Hdr + 36);
    int      ONet  = SWord(Hdr + 20), DNet  = SWord(Hdr + 22);
    int      OPt   = 0,               DPt   = 0;
    unsigned Cw    = Word(Hdr + 44),  CwCopy = Word(Hdr + 40);
    char * p;

    if((Cw & 1) != 0 && Cw == (((CwCopy & 0xFF) << 8) | (CwCopy >> 8)))
    {
        if(Word(Hdr + 46) != 0)
        {
            OZone = SWord(Hdr + 46);
            DZone = SWord(Hdr + 48);
        }

        OPt = SWord(Hdr + 50);
        DPt = SWord(Hdr + 52);

        if(OPt != 0 && ONet == -1)
        {
            ONet = SWord(Hdr + 38); /* FSC-0048 AuxNet */
        }
    }
    else if(Word(Hdr + 16) == 2)
    {
        OPt = SWord(Hdr + 4);
        DPt = SWord(Hdr + 6);
    }

    p  = Out + sprintf(Out, "%s (", Path);
    p  = FormatAddr(p, OZone, ONet, SWord(Hdr + 0), OPt);
    p += sprintf(p, " -> ");
    p  = FormatAddr(p, DZone, DNet, SWord(Hdr + 2), DPt);
    strcpy(p, ")");
}

/* Control characters -> '?' */
static void Clean(char * s)
{
    for(; *s != '\0'; s++)
    {
        if((unsigned char)*s < 0x20 || *s == 0x7F)
        {
            *s = '?';
        }
    }
}

/*
 * Logs modified message N of packet Path: "name.pkt#N: area tag, from
 * name (net/node) to name (net/node), subject "subject": truncating ...".
 * The area is from the AREA line (FTS-0004: the first line of the text);
 * without it the area is NETMAIL and the recipient has an address.
 */
static void LogMsg(const char * Path, long N, Msg * M)
{
    static char Line[LINE_SIZE + 384];
    const char * Area = NULL;
    const char * Sep = " ";
    char * p;
    int i;

    M->Text[strcspn(M->Text, "\r")] = '\0';
    Clean(M->Text);

    for(i = 0; i < 3; i++)
    {
        Clean(M->Str[i]);
    }

    if(strncmp(M->Text, "AREA:", 5) == 0)
    {
        Area = (M->Text[5] != '\0') ? M->Text + 5 : "<empty>";
    }

    p = Line + sprintf(Line, "area %s, from %s (%d/%d) to %s",
                       (Area != NULL) ? Area : "NETMAIL", M->Str[1],
                       SWord(M->Hdr + 6), SWord(M->Hdr + 2), M->Str[0]);

    if(Area == NULL)
    {
        p += sprintf(p, " (%d/%d)", SWord(M->Hdr + 8), SWord(M->Hdr + 4));
    }

    p += sprintf(p, ", subject \"%s\": truncating", M->Str[2]);

    for(i = 0; i < 3; i++)
    {
        if(M->Len[i] != 0)
        {
            p += sprintf(p, "%s%s %ld -> %ld", Sep, FieldName[i], M->Len[i],
                         FieldSize[i] - 1);
            Sep = ", ";
        }
    }

    Log(LOG_WARN, "%s#%ld: %s", BaseName(Path), N, Line);
}

/*
 * Reads the packet and finds the strings to truncate. A message cut off by
 * the end of the file is counted too, and its complete strings are
 * truncated; the start of such a message is the Tail. If F is not NULL,
 * logs each modified message, and the packet before the first one.
 */
static void ScanPacket(FILE * fh, const Files * F, Scan * S)
{
    static Msg M;
    long pos = 0, Cut = 0;
    int c;

    S->Tr      = NULL;
    S->TrCount = 0;
    S->NoMem   = 0;
    S->Msgs    = 0;
    S->Mod     = 0;
    S->Tail    = 0;
    S->B0      = EOF;
    S->B1      = EOF;

    while(pos < PKT_HDR_SIZE && (c = getc(fh)) != EOF)
    {
        S->Hdr[pos++] = (unsigned char)c;
    }

    /* packed messages, if the header is complete; left by break */
    while(pos >= PKT_HDR_SIZE)
    {
        long Start = pos;
        long First = S->TrCount; /* the first truncation in this message */
        int i;

        S->Tail = Start;
        S->B0   = getc(fh);
        S->B1   = (S->B0 == EOF) ? EOF : getc(fh);
        pos    += (S->B0 != EOF) + (S->B1 != EOF);

        if(S->B0 != 2 || S->B1 != 0)
        {
            break;
        }

        S->Msgs++;
        memset(&M, 0, sizeof(M));

        while(pos - Start < MSG_HDR_SIZE && (c = getc(fh)) != EOF)
        {
            M.Hdr[pos++ - Start] = (unsigned char)c;
        }

        if(pos - Start < MSG_HDR_SIZE)
        {
            break; /* cut off in the message header */
        }

        for(i = 0; i < 4; i++)
        {
            long f = pos;
            long l;
            Trunc * p;
            Trunc * t;

            while((c = getc(fh)) != EOF && c != 0)
            {
                if(i < 3 && pos - f < FieldSize[i] - 1)
                {
                    M.Str[i][pos - f] = (char)c;
                }
                else if(i == 3 && pos - f < LINE_SIZE - 1)
                {
                    M.Text[pos - f] = (char)c;
                }

                pos++;
            }

            if(c == EOF)
            {
                break; /* cut off: the unterminated string is kept as is */
            }

            pos++;
            l = pos - 1 - f;

            if(i == 3 || l <= FieldSize[i] - 1)
            {
                continue;
            }

            p = (Trunc *)Grow(S->Tr, S->TrCount, sizeof(Trunc));

            if(p == NULL)
            {
                S->NoMem = 1;
                break;
            }

            S->Tr    = p;
            t        = &S->Tr[S->TrCount++];
            t->at    = f + FieldSize[i] - 1;
            t->cut   = l - (FieldSize[i] - 1);
            M.Len[i] = l;
            Cut     += t->cut;
        }

        if(S->TrCount > First && !S->NoMem)
        {
            if(++S->Mod == 1 && F != NULL)
            {
                PktName(F->Name, F->Pkt, S->Hdr);
                Log(LOG_WARN, "%s: overlong field(s) detected", F->Name);
            }

            if(F != NULL)
            {
                LogMsg(F->Pkt, S->Msgs, &M);
            }
        }

        if(i < 4)
        {
            break;
        }
    }

    while(getc(fh) != EOF)
    {
        pos++;
    }

    S->Size   = pos;
    S->OutLen = pos - Cut;
}

/* Copies N bytes (all the rest if N < 0) from In to Out (skips if NULL) */
static int CopyBytes(FILE * In, FILE * Out, long N)
{
    static char Buf[4096];

    while(N != 0)
    {
        size_t k = (N < 0 || N > (long)sizeof(Buf)) ? sizeof(Buf) : (size_t)N;
        size_t r = fread(Buf, 1, k, In);

        if(Out != NULL && fwrite(Buf, 1, r, Out) != r)
        {
            return 0;
        }

        if(r < k)
        {
            return N < 0 && !ferror(In);
        }

        if(N > 0)
        {
            N -= (long)r;
        }
    }

    return 1;
}

/*
 * Writes packet Path without the truncated bytes to Tmp. If Tmp is opened
 * but not written completely, it is deleted. Returns 0 on error.
 */
static int WritePkt(const char * Path, const char * Tmp, const Scan * S)
{
    FILE * In;
    FILE * Out;
    long pos = 0, i;
    int Ok = 1;
    struct stat st;

    In = fopen(Path, "rb");

    if(In == NULL)
    {
        return 0;
    }

    Out = fopen(Tmp, "wb");

    if(Out == NULL)
    {
        fclose(In);
        return 0;
    }

    errno = 0; /* fopen() may set it even on success */

    for(i = 0; Ok && i < S->TrCount; i++)
    {
        const Trunc * t = &S->Tr[i];

        Ok  = CopyBytes(In, Out, t->at - pos) && CopyBytes(In, NULL, t->cut);
        pos = t->at + t->cut;
    }

    Ok = Ok && CopyBytes(In, Out, -1);
    fclose(In);
    Ok = (fflush(Out) == 0) && Ok;
    Ok = (fclose(Out) == 0) && Ok;
    Ok = Ok && stat(Tmp, &st) == 0 && (long)st.st_size == S->OutLen;

    if(!Ok)
    {
        int Err = errno;

        remove(Tmp);
        errno = Err;
    }

    return Ok;
}

/* Copies file From over file To, in place. Returns 0 on error. */
static int CopyFile(const char * From, const char * To)
{
    FILE * In;
    FILE * Out;
    int Ok;
    struct stat sf, st;

    In = fopen(From, "rb");

    if(In == NULL)
    {
        return 0;
    }

    Out = fopen(To, "wb");

    if(Out == NULL)
    {
        fclose(In);
        return 0;
    }

    errno = 0; /* fopen() may set it even on success */

    Ok = CopyBytes(In, Out, -1);
    fclose(In);
    Ok = (fflush(Out) == 0) && Ok;
    Ok = (fclose(Out) == 0) && Ok;
    return Ok && stat(From, &sf) == 0 && stat(To, &st) == 0 &&
           sf.st_size == st.st_size;
}

/*
 * Copies the processed packet Tmp over Path (Name for the log). If that
 * fails, Path is deleted, whatever it has become: then the next run renames
 * Tmp to it. Returns 0 on error.
 */
static int PutPkt(const char * Tmp, const char * Path, const char * Name)
{
    if(CopyFile(Tmp, Path))
    {
        return 1;
    }

    Log(LOG_ERR, "can't write %s: %s", Name,
        errno ? strerror(errno) : "read or write error");

    if(remove(Path) == 0)
    {
        Log(LOG_ERR, "deleted %s, it is restored from %s on the next run",
            Name, Tmp);
    }
    else
    {
        Log(LOG_ERR, "can't delete %s: %s, it is restored from %s on the "
            "next run", Name, strerror(errno), Tmp);
    }

    return 0;
}

/* 1 if Path exists, 0 if it does not, -1 if unknown (errno is set) */
static int Exists(const char * Path)
{
    struct stat st;

    if(stat(Path, &st) == 0)
    {
        return 1;
    }

    return errno == ENOENT ? 0 : -1;
}

/*
 * Out = an unused name with extension Ext (4 characters) in the directory
 * of file Path: "XXXXXXXX.ext" with the directory. Out has room for
 * strlen(Path) + 13 bytes. Returns 0 if none is found.
 */
static int UniqueName(char * Out, const char * Path, const char * Ext)
{
    unsigned long n = (unsigned long)time(NULL);
    char Name[16];
    int i;

    for(i = 0; i < 1000; i++)
    {
        sprintf(Name, "%08lx%s", (n + i) & 0xFFFFFFFFUL, Ext);
        SameDir(Out, Path, Name);

        if(Exists(Out) == 0)
        {
            return 1;
        }
    }

    return 0;
}

/*
 * Renames packet F->Pkt that needs changes but can't be changed to F->Bad,
 * or to an unused .bad name if that one exists, so that the tosser does not
 * get it, and logs it as an error: F->Why for the packet F->Name.
 */
static void BadPkt(const Files * F)
{
    const char * Bad = F->Bad;
    const char * Name = F->Name;
    const char * Why = F->Why;

    if(Exists(Bad) != 0)
    {
        Bad = UniqueName(F->New, F->Pkt, ".bad") ? F->New : NULL;
    }

    if(Bad == NULL)
    {
        Log(LOG_ERR, "%s: %s, no unused .bad name found for it", Name, Why);
    }
    else if(rename(F->Pkt, Bad) == 0)
    {
        Log(LOG_ERR, "%s: %s, renamed to %s", Name, Why, Bad);
    }
    else
    {
        Log(LOG_ERR, "%s: %s, can't rename it to %s: %s", Name, Why, Bad,
            strerror(errno));
    }
}

/*
 * Writes the truncated packet F->Pkt to F->Tmp, copies it over F->Pkt,
 * restores the file time from st and deletes F->Tmp. If F->Tmp exists (e.g.
 * kept by RestoreTmp()) or can't be written, the packet is renamed to .bad.
 * Returns 0 on error.
 */
static int ReplacePkt(const Files * F, const Scan * S, const struct stat * st)
{
    const char * Path = F->Pkt;
    const char * Tmp = F->Tmp;
    const char * Name = F->Name;
    struct utimbuf ut;
    const char * Fmt = NULL;
    const char * Err = "";
    int e = Exists(Tmp);

    /* No Tmp: the packet is written to it */
    if(e == 0)
    {
        if(!WritePkt(Path, Tmp, S))
        {
            Fmt = "can't write %s: %.200s";
            Err = errno ? strerror(errno) : "read or write error";
        }
    }
    /* Tmp exists */
    else if(e == 1)
    {
        Fmt = "temporary file %s exists%s";
    }
    /* Unknown if Tmp exists (-1), or an unexpected result */
    else
    {
        if(e != -1)
        {
            Unexpected("Exists() result", e, -1);
        }

        Fmt = "can't stat %s: %.200s";
        Err = strerror(errno);
    }

    if(Fmt != NULL)
    {
        sprintf(F->Why, Fmt, Tmp, Err);
        BadPkt(F);
        return 0;
    }

    if(!PutPkt(Tmp, Path, Name))
    {
        return 0;
    }

    ut.actime  = st->st_atime;
    ut.modtime = st->st_mtime;

    if(utime(Path, &ut) != 0)
    {
        Log(LOG_WARN, "can't restore the file time of %s: %s", Name,
            strerror(errno));
    }

    if(remove(Tmp) != 0)
    {
        Log(LOG_WARN, "can't delete temporary file %s: %s", Tmp,
            strerror(errno));
    }

    return 1;
}

/* Processes packet F->Pkt. Returns 0 on success, 1 on error. */
static int ProcessPacket(const Files * F)
{
    const char * Path = F->Pkt;
    const char * Name = F->Name;
    struct stat st;
    FILE * fh;
    Scan S;
    long Rest;
    int Bad;
    int Rc = 1;

    S.Tr = NULL;

    if(stat(Path, &st) != 0)
    {
        Log(LOG_ERR, "can't stat %s: %s, skipped", Path, strerror(errno));
        goto done;
    }

    fh = fopen(Path, "rb");

    if(fh == NULL)
    {
        Log(LOG_ERR, "can't read %s: %s, skipped", Path, strerror(errno));
        goto done;
    }

    errno = 0; /* fopen() may set it even on success */

    ScanPacket(fh, F, &S);
    Bad = ferror(fh);
    fclose(fh);

    if(Bad)
    {
        Log(LOG_ERR, "can't read %s: %s, skipped", Path,
            errno ? strerror(errno) : "read error");
        goto done;
    }

    if(S.Size < PKT_HDR_SIZE)
    {
        Log(LOG_ERR, "%s is not a packet: only %ld bytes, shorter than a "
            "packet header, skipped", Path, S.Size);
        goto done;
    }

    PktName(F->Name, Path, S.Hdr);
    Rest = S.Size - S.Tail;

    if(S.NoMem)
    {
        sprintf(F->Why, "not enough memory to truncate more than %ld strings",
                S.TrCount);
        BadPkt(F);
        goto done;
    }

    if(Rest == 2 && S.B0 == 0 && S.B1 == 0)
    {
        /* a proper packet terminator */
    }
    else if(S.Msgs == 0)
    {
        Log(LOG_ERR, "%s is not a packet: no packed messages after the packet "
            "header (%ld bytes of unknown data at offset %ld), skipped", Name,
            Rest, S.Tail);
        goto done;
    }
    else if(S.B0 == 2 && S.B1 == 0)
    {
        Log(LOG_WARN, "%s: message #%ld (offset %ld) is cut off by the end of "
            "the file, its unterminated part is kept as is", Name, S.Msgs,
            S.Tail);
    }
    else if(Rest == 0)
    {
        Log(LOG_WARN, "%s: no packet terminator, the file ends right after "
            "message #%ld", Name, S.Msgs);
    }
    else if(Rest == 1 && S.B0 == 0)
    {
        Log(LOG_WARN, "%s: incomplete packet terminator after message #%ld "
            "(1 byte at offset %ld), kept as is", Name, S.Msgs, S.Tail);
    }
    else if(Rest > 2 && S.B0 == 0 && S.B1 == 0)
    {
        Log(LOG_WARN, "%s: %ld bytes of unknown data after the packet "
            "terminator (offset %ld), kept as is", Name, Rest - 2,
            S.Tail + 2);
    }
    else
    {
        Log(LOG_WARN, "%s: unknown data instead of a packet terminator after "
            "message #%ld (%ld bytes at offset %ld), kept as is without "
            "parsing", Name, S.Msgs, Rest, S.Tail);
    }

    if(S.TrCount > 0 && !ReplacePkt(F, &S, &st))
    {
        goto done;
    }

    Log(LOG_INFO, "processed %s: messages %ld, modified %ld", Name, S.Msgs,
        S.Mod);
    Rc = 0;

done:
    free(S.Tr);
    return Rc;
}

/* ------------------------------------------------------------------ */
/* Directory scanning                                                 */

/*
 * Compares files A and B: 0 if they are the same, 1 if A is the start of B,
 * 2 if B is the start of A, 3 otherwise, -1 on a read error.
 */
static int CompareFiles(const char * A, const char * B)
{
    FILE * a = fopen(A, "rb");
    FILE * b = fopen(B, "rb");
    int ca, cb;
    int Rc = -1;

    if(a != NULL && b != NULL)
    {
        do
        {
            ca = getc(a);
            cb = getc(b);
        }
        while(ca == cb && ca != EOF);

        if(!ferror(a) && !ferror(b))
        {
            Rc = (ca == cb) ? 0 : (ca == EOF) ? 1 : (cb == EOF) ? 2 : 3;
        }
    }

    if(a != NULL)
    {
        fclose(a);
    }

    if(b != NULL)
    {
        fclose(b);
    }

    return Rc;
}

/* Writes packet Path processed again to Out, not logged. 0 on error. */
static int Reprocess(const char * Path, const char * Out)
{
    FILE * fh = fopen(Path, "rb");
    Scan S;
    int Ok;

    if(fh == NULL)
    {
        return 0;
    }

    ScanPacket(fh, NULL, &S);
    Ok = !ferror(fh) && !S.NoMem;
    fclose(fh);
    Ok = Ok && WritePkt(Path, Out, &S);
    free(S.Tr);
    return Ok;
}

/*
 * Compares temporary file PTmp with its packet PPkt processed again to
 * PChk ($pktsan$.tmp); PNew has room for an unused packet name (see
 * UniqueName()):
 *   - the same, or the start of PTmp: the packet was being rewritten, PTmp
 *     is copied over it;
 *   - PTmp is the start of it: PTmp was being written, it is deleted;
 *   - neither is the start of the other: PTmp is kept as a packet with an
 *     unused name;
 *   - they can't be compared: PTmp is kept.
 * Returns 0 on success, 1 on error.
 */
static int CompareTmp(const char * PTmp, const char * PPkt,
                      const char * PChk, char * PNew)
{
    int Cmp;
    int Rc = 1;

    errno = 0;
    Cmp = Reprocess(PPkt, PChk) ? CompareFiles(PChk, PTmp) : -1;

    /* The processed packet is the same as the temporary file or its start:
       the packet was being rewritten from the temporary file */
    if(Cmp == 0 || Cmp == 1)
    {
        if(PutPkt(PTmp, PPkt, PPkt))
        {
            Log(LOG_WARN, "restored %s from temporary file %s", PPkt, PTmp);
            Rc = 0;

            if(remove(PTmp) != 0)
            {
                Log(LOG_WARN, "can't delete temporary file %s: %s", PTmp,
                    strerror(errno));
            }
        }
    }
    /* The temporary file is the start of the processed packet: it was being
       written, the packet is not changed yet */
    else if(Cmp == 2)
    {
        if(remove(PTmp) == 0)
        {
            Log(LOG_WARN, "deleted incomplete temporary file %s", PTmp);
            Rc = 0;
        }
        else
        {
            Log(LOG_ERR, "can't delete temporary file %s: %s", PTmp,
                strerror(errno));
        }
    }
    /* Neither is the start of the other: the temporary file is not from this
       packet, it is kept as a packet with an unused name */
    else if(Cmp == 3)
    {
        /* No unused packet name is found */
        if(!UniqueName(PNew, PTmp, ".pkt"))
        {
            Log(LOG_ERR, "temporary file %s does not match %s and no unused "
                "packet name is found for it, kept", PTmp, PPkt);
        }
        /* Renamed to an unused packet name */
        else if(rename(PTmp, PNew) == 0)
        {
            Log(LOG_WARN, "temporary file %s does not match %s, kept as %s",
                PTmp, PPkt, PNew);
            Rc = 0;
        }
        /* Can't be renamed to the unused name */
        else
        {
            Log(LOG_ERR, "can't rename temporary file %s to %s: %s, kept",
                PTmp, PNew, strerror(errno));
        }
    }
    /* The packet can't be processed again or the files can't be compared
       (-1), or an unexpected result: the temporary file is kept */
    else
    {
        if(Cmp != -1)
        {
            Unexpected("CompareFiles() result", Cmp, -1);
        }

        Log(LOG_ERR, "can't compare temporary file %s with %s: %s, kept",
            PTmp, PPkt,
            errno ? strerror(errno) : "read, write or memory error");
    }

    remove(PChk);
    return Rc;
}

/*
 * Handles temporary file F->Tmp left by an interrupted run. Without its
 * packet it is renamed to the packet, otherwise see CompareTmp(). Returns 0
 * on success, 1 on error.
 */
static int RestoreTmp(const Files * F, const char * PChk)
{
    const char * PTmp = F->Tmp;
    const char * PPkt = F->Pkt;
    int e = Exists(PPkt);
    int Rc = 1;

    /* No packet: the temporary file is renamed to it */
    if(e == 0)
    {
        if(rename(PTmp, PPkt) == 0)
        {
            Log(LOG_WARN, "restored %s from temporary file %s", PPkt, PTmp);
            Rc = 0;
        }
        else
        {
            Log(LOG_ERR, "can't restore %s from temporary file %s: %s, "
                "retried on the next run", PPkt, PTmp, strerror(errno));
        }
    }
    /* The packet exists: it is processed again and compared */
    else if(e == 1)
    {
        Rc = CompareTmp(PTmp, PPkt, PChk, F->New);
    }
    /* Unknown if the packet exists (-1), or an unexpected result: rename()
       could replace a packet that does exist, the temporary file is kept */
    else
    {
        if(e != -1)
        {
            Unexpected("Exists() result", e, -1);
        }

        Log(LOG_ERR, "can't stat %s: %s, temporary file %s kept", PPkt,
            strerror(errno), PTmp);
    }

    return Rc;
}

/*
 * Fills F for file Name in Dir: the packet if Tmp is 0, its temporary file
 * otherwise. All the names are in one block, freed with free(F->Pkt).
 */
static void NewFiles(Files * F, const char * Dir, const char * Name, int Tmp)
{
    size_t l = strlen(Dir) + strlen(Name) + 2; /* a path in Dir, null too */
    char * Own;
    char * Pair;

    F->Pkt  = (char *)AllocOrDie(6 * l + 336);
    F->Tmp  = F->Pkt + l;
    F->Bad  = F->Tmp + l;
    F->New  = F->Bad + l;           /* XXXXXXXX.ext: up to l + 13 */
    F->Name = F->New + l + 16;      /* the packet addresses: up to 64 */
    F->Why  = F->Name + l + 64;     /* a path, up to 256 more */

    Own  = Tmp ? F->Tmp : F->Pkt;   /* the file from the listing */
    Pair = Tmp ? F->Pkt : F->Tmp;
    JoinPath(Own, Dir, Name);
    strcpy(Pair, Own);
    SwapExt(Pair);
    strcpy(F->Bad, F->Pkt);
    strcpy(F->Bad + strlen(F->Bad) - 4, ".bad");
}

/*
 * Path is not a directory or another special file. If stat() fails, it
 * counts as a file: processing it logs the error.
 */
static int IsFile(const char * Path)
{
    struct stat st;

    return stat(Path, &st) != 0 || S_ISREG(st.st_mode);
}

/*
 * Processes directory Dir. Returns the number of errors. The directory is
 * listed twice: first the temporary files left by an interrupted run are
 * handled, then the packets are processed. Processing a packet does not
 * change its directory entry: it is rewritten in place.
 */
static int ProcessDir(const char * Dir)
{
    char * Chk;
    int Errors = 0;
    DIR * d;
    struct dirent * de;
    Files F;

    Log(LOG_INFO, "processing directory %s", Dir);
    d = opendir(Dir);

    if(d == NULL)
    {
        Log(LOG_ERR, "can't read directory %s: %s", Dir, strerror(errno));
        return 1;
    }

    /* left if a run was interrupted while handling a temporary file */
    Chk = (char *)AllocOrDie(strlen(Dir) + 14);
    JoinPath(Chk, Dir, "$pktsan$.tmp");
    remove(Chk);

    while((de = readdir(d)) != NULL)
    {
        if(HasExt(de->d_name, ".tr$") || HasExt(de->d_name, ".tr#"))
        {
            NewFiles(&F, Dir, de->d_name, 1);

            if(IsFile(F.Tmp))
            {
                Errors += RestoreTmp(&F, Chk);
            }

            free(F.Pkt);
        }
    }

    closedir(d);
    d = opendir(Dir);

    if(d == NULL)
    {
        Log(LOG_ERR, "can't read directory %s: %s", Dir, strerror(errno));
        free(Chk);
        return Errors + 1;
    }

    while((de = readdir(d)) != NULL)
    {
        if(HasExt(de->d_name, ".pkt"))
        {
            NewFiles(&F, Dir, de->d_name, 0);

            if(IsFile(F.Pkt))
            {
                Errors += ProcessPacket(&F);
            }

            free(F.Pkt);
        }
    }

    closedir(d);
    free(Chk);
    return Errors;
}

/* ------------------------------------------------------------------ */

static void Usage(FILE * fh)
{
    fprintf(fh, "PKT Sanitizer " VERSION " - truncate too long names and "
            "subjects in FTS-0001 packets\n\n"
            "Usage: " PROGNAME " [-c config] dir...\n\n"
            "Processes all *.pkt files in the given directories. The default\n"
            "config is " CONFIGNAME " in the program directory.\n");
}

int main(int argc, char ** argv)
{
    char * DefCfg = NULL;
    char * LogFile = NULL;
    const char * Cfg = NULL;
    int Errors = 0;
    int c, i;

    while((c = getopt(argc, argv, "c:h")) != -1)
    {
        switch(c)
        {
            case 'c':
                Cfg = optarg;
                break;

            case 'h':
                Usage(stdout);
                return 0;

            default: /* getopt() has printed the error */
                return 1;
        }
    }

    if(optind >= argc)
    {
        Usage(stderr);
        return 1;
    }

    if(Cfg == NULL)
    {
        /* CONFIGNAME in the directory of the program */
        DefCfg = (char *)AllocOrDie(strlen(argv[0]) + sizeof(CONFIGNAME));
        SameDir(DefCfg, argv[0], CONFIGNAME);
    }

    if(ReadConfig(Cfg != NULL ? Cfg : DefCfg, Cfg != NULL, &LogFile) != 0)
    {
        free(DefCfg);
        free(LogFile);
        return 1;
    }

    if(LogFile != NULL)
    {
        LogFh = fopen(LogFile, "a");

        if(LogFh == NULL)
        {
            fprintf(stderr, PROGNAME ": can't open log '%s': %s\n", LogFile,
                    strerror(errno));
            free(DefCfg);
            free(LogFile);
            return 1;
        }
    }

    for(i = optind; i < argc; i++)
    {
        Errors += ProcessDir(argv[i]);
    }

    if(LogFh != NULL)
    {
        fclose(LogFh);
    }

    free(DefCfg);
    free(LogFile);
    return Errors ? 1 : 0;
}

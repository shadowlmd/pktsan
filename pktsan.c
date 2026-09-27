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
 * A packet is rewritten only when something has to be truncated: the new
 * packet is written to name.tr$, then name.pkt is deleted and name.tr$ is
 * renamed to name.pkt. A name.tr$ left by an interrupted run is deleted if
 * its packet still exists and renamed back to name.pkt otherwise.
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

/* MinGW, Watcom, Borland, DJGPP and EMX have stricmp(), Unix strcasecmp() */
#if defined(__unix__) || defined(__APPLE__)
#include <strings.h>
#define stricmp strcasecmp
#endif

#define PROGNAME    "pktsan"
#define VERSION     "1.0"
#define CONFIGNAME  "pktsan.cfg"

#define PKT_HDR_SIZE 58   /* packet header */
#define MSG_HDR_SIZE 34   /* messageType .. DateTime */

#define LOG_ERR   0   /* a packet or a file is skipped */
#define LOG_WARN  1   /* a problem pktsan fixed or worked around */
#define LOG_INFO  2   /* processed packets */

static FILE * LogFh    = NULL;
static int    LogLevel = LOG_INFO;

static const char * FieldName[3] = { "toUserName", "fromUserName", "subject" };
static const long   FieldSize[3] = { 36, 36, 72 };

typedef struct
{
    long msg;      /* message number in the packet, from 1 */
    int  field;    /* index in FieldName */
    long len;      /* original length without the null */
    long at;       /* offset of the first byte cut off */
} Trunc;

/* ------------------------------------------------------------------ */

static void Log(int Level, const char * Fmt, ...)
{
    static const char * Names[] = { "err", "warn", "info" };
    va_list ap;
    time_t t;
    struct tm * tm;
    char Stamp[32] = "0000-00-00 00:00:00";
    FILE * fh;

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
}

static void * Alloc(size_t Size)
{
    void * p = malloc(Size);

    if(p == NULL)
    {
        fprintf(stderr, PROGNAME ": out of memory\n");
        exit(1);
    }

    return p;
}

static char * StrDup(const char * s)
{
    return strcpy((char *)Alloc(strlen(s) + 1), s);
}

/* "name.xxx" -> "name" + Ext */
static char * ChangeExt(const char * Name, const char * Ext)
{
    size_t l = strlen(Name) - 4;
    char * p = (char *)Alloc(l + strlen(Ext) + 1);

    memcpy(p, Name, l);
    strcpy(p + l, Ext);
    return p;
}

/* Dir + separator + Name; the separator follows the style of Dir */
static char * JoinPath(const char * Dir, const char * Name)
{
    size_t l = strlen(Dir);
    char Sep = (strchr(Dir, '\\') != NULL && strchr(Dir, '/') == NULL) ?
               '\\' : '/';
    char * p = (char *)Alloc(l + 1 + strlen(Name) + 1);

    strcpy(p, Dir);

    if(l > 0 && Dir[l - 1] != Sep && Dir[l - 1] != ':')
    {
        p[l++] = Sep;
    }

    strcpy(p + l, Name);
    return p;
}

static int HasExt(const char * Name, const char * Ext)
{
    size_t l = strlen(Name);

    return l >= 4 && stricmp(Name + l - 4, Ext) == 0;
}

/* ------------------------------------------------------------------ */
/* Configuration                                                      */

/* Name in the directory of Path: "dir/file" + Name -> "dir/Name" */
static char * SameDir(const char * Path, const char * Name)
{
    size_t l = strlen(Path);
    char * p;

    while(l > 0 && Path[l - 1] != '/' && Path[l - 1] != '\\' &&
          Path[l - 1] != ':')
    {
        l--;
    }

    p = (char *)Alloc(l + strlen(Name) + 1);
    memcpy(p, Path, l);
    strcpy(p + l, Name);
    return p;
}

static int IsAbsolute(const char * Path)
{
    return Path[0] == '/' || Path[0] == '\\' ||
           (Path[0] != '\0' && Path[1] == ':');
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

/* Returns 0 on success. A missing config is fine unless Required. */
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
            *LogFile = IsAbsolute(Val) ? StrDup(Val) : SameDir(Path, Val);
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

/*
 * Reads the packet and finds the strings to truncate. Truncations are
 * stored to *Tr (allocated) in file order, their number to *TrCount.
 * A message cut off by the end of the file is counted too, and its complete
 * strings are truncated. *Size is the file size, *Tail the offset of the
 * data after the last complete message (the start of the cut off message,
 * if any), *B0 and *B1 the first two bytes there (EOF if none).
 * Returns the number of messages.
 */
static long ScanPacket(FILE * fh, long * Size, long * Tail, int * B0, int * B1,
                       Trunc ** Tr, long * TrCount)
{
    long pos = 0, Msgs = 0, TrAlloc = 0;
    int c;

    *Tr      = NULL;
    *TrCount = 0;
    *Tail    = 0;
    *B0      = EOF;
    *B1      = EOF;

    while(pos < PKT_HDR_SIZE && getc(fh) != EOF)
    {
        pos++;
    }

    /* packed messages, if the header is complete; left by break */
    while(pos >= PKT_HDR_SIZE)
    {
        long Start = pos;
        int i;

        *Tail = Start;
        *B0   = getc(fh);
        *B1   = (*B0 == EOF) ? EOF : getc(fh);
        pos  += (*B0 != EOF) + (*B1 != EOF);

        if(*B0 != 2 || *B1 != 0)
        {
            break;
        }

        Msgs++;

        while(pos - Start < MSG_HDR_SIZE && getc(fh) != EOF)
        {
            pos++;
        }

        if(pos - Start < MSG_HDR_SIZE)
        {
            break; /* cut off in the message header */
        }

        for(i = 0; i < 4; i++)
        {
            long f = pos;
            long l;

            while((c = getc(fh)) != EOF && c != 0)
            {
                pos++;
            }

            if(c == EOF)
            {
                break; /* cut off: the unterminated string is kept as is */
            }

            pos++;
            l = pos - 1 - f;

            if(i < 3 && l > FieldSize[i] - 1)
            {
                if(*TrCount == TrAlloc)
                {
                    Trunc * t;

                    TrAlloc = TrAlloc ? TrAlloc * 2 : 16;
                    t = (Trunc *)realloc(*Tr, TrAlloc * sizeof(Trunc));

                    if(t == NULL)
                    {
                        fprintf(stderr, PROGNAME ": out of memory\n");
                        exit(1);
                    }

                    *Tr = t;
                }

                (*Tr)[*TrCount].msg   = Msgs;
                (*Tr)[*TrCount].field = i;
                (*Tr)[*TrCount].len   = l;
                (*Tr)[*TrCount].at    = f + FieldSize[i] - 1;
                (*TrCount)++;
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

    *Size = pos;
    return Msgs;
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

/* Writes packet Path without the truncated bytes to Tmp */
static int WritePkt(const char * Path, const char * Tmp, const Trunc * Tr,
                    long TrCount, long OutLen)
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

    for(i = 0; Ok && i < TrCount; i++)
    {
        long Cut = Tr[i].len - (FieldSize[Tr[i].field] - 1);

        Ok = CopyBytes(In, Out, Tr[i].at - pos) && CopyBytes(In, NULL, Cut);
        pos = Tr[i].at + Cut;
    }

    Ok = Ok && CopyBytes(In, Out, -1);
    fclose(In);
    Ok = (fflush(Out) == 0) && Ok;
    Ok = (fclose(Out) == 0) && Ok;
    return Ok && stat(Tmp, &st) == 0 && (long)st.st_size == OutLen;
}

/* Path and Tmp include the directory. Returns 0 on success, 1 on error. */
static int ProcessPacket(const char * Path, const char * Tmp)
{
    struct stat st;
    FILE * fh;
    Trunc * Tr = NULL;
    long Size, TrCount, Msgs, Tail, Rest, OutLen, Mod, i;
    int B0, B1, Bad;
    struct utimbuf ut;
    int Rc = 1;

    errno = 0;

    if(stat(Path, &st) != 0)
    {
        Log(LOG_ERR, "can't stat %s: %s, skipped", Path, strerror(errno));
        goto done;
    }

    errno = 0;
    fh = fopen(Path, "rb");

    if(fh == NULL)
    {
        Log(LOG_ERR, "can't read %s: %s, skipped", Path, strerror(errno));
        goto done;
    }

    errno = 0; /* fopen() may set it even on success */

    Msgs = ScanPacket(fh, &Size, &Tail, &B0, &B1, &Tr, &TrCount);
    Bad  = ferror(fh);
    fclose(fh);

    if(Bad)
    {
        Log(LOG_ERR, "can't read %s: %s, skipped", Path,
            errno ? strerror(errno) : "read error");
        goto done;
    }

    if(Size < PKT_HDR_SIZE)
    {
        Log(LOG_ERR, "%s is not a packet: only %ld bytes, shorter than a packet "
            "header, skipped", Path, Size);
        goto done;
    }

    Rest = Size - Tail;

    if(Rest == 2 && B0 == 0 && B1 == 0)
    {
        /* a proper packet terminator */
    }
    else if(Msgs == 0)
    {
        Log(LOG_ERR, "%s is not a packet: no packed messages after the packet "
            "header (%ld bytes of unknown data at offset %ld), skipped", Path,
            Rest, Tail);
        goto done;
    }
    else if(B0 == 2 && B1 == 0)
    {
        Log(LOG_WARN, "%s: message #%ld (offset %ld) is cut off by the end of "
            "the file, its unterminated part is kept as is", Path, Msgs, Tail);
    }
    else if(Rest == 0)
    {
        Log(LOG_WARN, "%s: no packet terminator, the file ends right after "
            "message #%ld", Path, Msgs);
    }
    else if(Rest == 1 && B0 == 0)
    {
        Log(LOG_WARN, "%s: incomplete packet terminator after message #%ld "
            "(1 byte at offset %ld), kept as is", Path, Msgs, Tail);
    }
    else if(Rest > 2 && B0 == 0 && B1 == 0)
    {
        Log(LOG_WARN, "%s: %ld bytes of unknown data after the packet "
            "terminator (offset %ld), kept as is", Path, Rest - 2, Tail + 2);
    }
    else
    {
        Log(LOG_WARN, "%s: unknown data instead of a packet terminator after "
            "message #%ld (%ld bytes at offset %ld), kept as is without "
            "parsing", Path, Msgs, Rest, Tail);
    }

    if(TrCount == 0)
    {
        Log(LOG_INFO, "processed %s: messages %ld, modified 0", Path, Msgs);
        Rc = 0;
        goto done;
    }

    OutLen = Size;

    for(i = 0; i < TrCount; i++)
    {
        OutLen -= Tr[i].len - (FieldSize[Tr[i].field] - 1);
    }

    errno = 0;

    if(!WritePkt(Path, Tmp, Tr, TrCount, OutLen))
    {
        Log(LOG_ERR, "can't write %s: %s, %s skipped", Tmp,
            errno ? strerror(errno) : "read or write error", Path);
        remove(Tmp);
        goto done;
    }

    errno = 0;

    if(remove(Path) != 0)
    {
        Log(LOG_ERR, "can't delete %s: %s, skipped", Path,
            strerror(errno));
        remove(Tmp);
        goto done;
    }

    if(rename(Tmp, Path) != 0)
    {
        /* Tmp is complete: it is renamed back on the next run */
        Log(LOG_ERR, "can't rename %s to %s: %s, the processed packet is "
            "restored from %s on the next run", Tmp, Path, strerror(errno),
            Tmp);
        goto done;
    }

    ut.actime  = st.st_atime;
    ut.modtime = st.st_mtime;
    errno = 0;

    if(utime(Path, &ut) != 0)
    {
        Log(LOG_WARN, "can't restore the file time of %s: %s", Path,
            strerror(errno));
    }

    for(i = 0; i < TrCount; i++)
    {
        Log(LOG_WARN, "truncated %s to %ld bytes (was %ld) in message #%ld "
            "in %s", FieldName[Tr[i].field], FieldSize[Tr[i].field] - 1,
            Tr[i].len, Tr[i].msg, Path);
    }

    /* truncations are in message order */
    for(i = 0, Mod = 0; i < TrCount; i++)
    {
        Mod += (i == 0 || Tr[i].msg != Tr[i - 1].msg);
    }

    Log(LOG_INFO, "processed %s: messages %ld, modified %ld", Path, Msgs,
        Mod);
    Rc = 0;

done:
    free(Tr);
    return Rc;
}

/* ------------------------------------------------------------------ */
/* Directory scanning                                                 */

static void AddName(char *** List, long * Count, long * Size, char * Name)
{
    if(*Count == *Size)
    {
        char ** l;

        *Size = *Size ? *Size * 2 : 64;
        l = (char **)realloc(*List, *Size * sizeof(char *));

        if(l == NULL)
        {
            fprintf(stderr, PROGNAME ": out of memory\n");
            exit(1);
        }

        *List = l;
    }

    (*List)[(*Count)++] = Name;
}

static int HasName(char ** List, long Count, const char * Name)
{
    long i;

    for(i = 0; i < Count; i++)
    {
        if(stricmp(List[i], Name) == 0)
        {
            return 1;
        }
    }

    return 0;
}

/* Processes directory Dir. Returns the number of errors. */
static int ProcessDir(const char * Dir)
{
    char ** Pkts = NULL;
    char ** Tmps = NULL;
    long NPkts = 0, SPkts = 0, NTmps = 0, STmps = 0, i;
    int Errors = 0;
    DIR * d;
    struct dirent * de;

    Log(LOG_INFO, "processing directory %s", Dir);
    errno = 0;
    d = opendir(Dir);

    if(d == NULL)
    {
        Log(LOG_ERR, "can't read directory %s: %s", Dir, strerror(errno));
        return 1;
    }

    while((de = readdir(d)) != NULL)
    {
        int Pkt = HasExt(de->d_name, ".pkt");

        if(Pkt || HasExt(de->d_name, ".tr$"))
        {
            char * Path = JoinPath(Dir, de->d_name);
            struct stat st;
            /* a packet that can't be stat'ed is logged when processed */
            int Reg = stat(Path, &st) != 0 || S_ISREG(st.st_mode);

            if(Reg && Pkt)
            {
                AddName(&Pkts, &NPkts, &SPkts, StrDup(de->d_name));
            }
            else if(Reg)
            {
                AddName(&Tmps, &NTmps, &STmps, StrDup(de->d_name));
            }

            free(Path);
        }
    }

    closedir(d);

    /* temporary files left by an interrupted run */
    for(i = 0; i < NTmps; i++)
    {
        char * Name  = ChangeExt(Tmps[i], ".pkt");
        char * PTmp  = JoinPath(Dir, Tmps[i]);
        char * PName = JoinPath(Dir, Name);

        if(HasName(Pkts, NPkts, Name))
        {
            if(remove(PTmp) == 0)
            {
                Log(LOG_WARN, "deleted incomplete temporary file %s", PTmp);
            }
            else
            {
                Log(LOG_ERR, "can't delete temporary file %s: %s", PTmp,
                    strerror(errno));
                Errors++;
            }

            free(Name);
        }
        else if(rename(PTmp, PName) == 0)
        {
            Log(LOG_WARN, "restored %s from temporary file %s", PName, PTmp);
            AddName(&Pkts, &NPkts, &SPkts, Name);
        }
        else
        {
            Log(LOG_ERR, "can't restore %s from temporary file %s: %s, "
                "retried on the next run", PName, PTmp, strerror(errno));
            Errors++;
            free(Name);
        }

        free(PTmp);
        free(PName);
        free(Tmps[i]);
    }

    free(Tmps);

    for(i = 0; i < NPkts; i++)
    {
        char * Tmp   = ChangeExt(Pkts[i], ".tr$");
        char * PPkt  = JoinPath(Dir, Pkts[i]);
        char * PTmp  = JoinPath(Dir, Tmp);

        Errors += ProcessPacket(PPkt, PTmp);
        free(PPkt);
        free(PTmp);
        free(Tmp);
        free(Pkts[i]);
    }

    free(Pkts);
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
    char * Cfg = NULL;
    char * LogFile = NULL;
    int CfgRequired = 0;
    int Errors = 0;
    int c, i;

    while((c = getopt(argc, argv, "c:h")) != -1)
    {
        switch(c)
        {
            case 'c':
                free(Cfg);
                Cfg = StrDup(optarg);
                CfgRequired = 1;
                break;

            case 'h':
                free(Cfg);
                Usage(stdout);
                return 0;

            default: /* getopt() has printed the error */
                free(Cfg);
                return 1;
        }
    }

    if(optind >= argc)
    {
        free(Cfg);
        Usage(stderr);
        return 1;
    }

    if(Cfg == NULL)
    {
        /* CONFIGNAME in the directory of the program */
        Cfg = SameDir(argv[0], CONFIGNAME);
    }

    if(ReadConfig(Cfg, CfgRequired, &LogFile) != 0)
    {
        free(Cfg);
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
            free(Cfg);
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

    free(Cfg);
    free(LogFile);
    return Errors ? 1 : 0;
}

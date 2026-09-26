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
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <utime.h>

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
} Trunc;

/* ------------------------------------------------------------------ */

static void Log(int Level, const char * Fmt, ...)
{
    static const char * Names[] = { "err", "warn", "info" };
    va_list ap;
    time_t t;
    char Stamp[32];
    FILE * fh;

    if(Level > LogLevel)
    {
        return;
    }

    fh = (LogFh != NULL) ? LogFh : stdout;
    t  = time(NULL);
    strftime(Stamp, sizeof(Stamp), "%Y-%m-%d %H:%M:%S", localtime(&t));
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

static int StrICmp(const char * a, const char * b)
{
    while(*a != '\0' && tolower((unsigned char)*a) == tolower((unsigned char)*b))
    {
        a++;
        b++;
    }

    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
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

static int HasExt(const char * Name, const char * Ext)
{
    size_t l = strlen(Name);

    return l >= 4 && StrICmp(Name + l - 4, Ext) == 0;
}

/* ------------------------------------------------------------------ */
/* Configuration                                                      */

/* CONFIGNAME in the directory of the program */
static char * ConfigPath(const char * Argv0)
{
    size_t l = strlen(Argv0);
    char * p;

    while(l > 0 && Argv0[l - 1] != '/' && Argv0[l - 1] != '\\' &&
          Argv0[l - 1] != ':')
    {
        l--;
    }

    p = (char *)Alloc(l + strlen(CONFIGNAME) + 1);
    memcpy(p, Argv0, l);
    strcpy(p + l, CONFIGNAME);
    return p;
}

static char * Trim(char * s)
{
    char * e;

    while(*s == ' ' || *s == '\t')
    {
        s++;
    }

    e = s + strlen(s);

    while(e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' ||
                    e[-1] == '\n'))
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

        for(Val = Key; *Val != '\0' && *Val != ' ' && *Val != '\t'; Val++)
        {
        }

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

        if(StrICmp(Key, "LogFile") == 0 && *Val != '\0')
        {
            free(*LogFile);
            *LogFile = StrDup(Val);
        }
        else if(StrICmp(Key, "LogLevel") == 0 && StrICmp(Val, "info") == 0)
        {
            LogLevel = LOG_INFO;
        }
        else if(StrICmp(Key, "LogLevel") == 0 && StrICmp(Val, "warn") == 0)
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
 * Copies packet In to Out (at most InLen bytes) truncating too long strings.
 * Truncations are stored to *Tr (allocated), their number to *TrCount.
 * A message cut off by the end of the file is counted too: its complete
 * strings are truncated and the rest is copied as is. *Tail is the offset
 * of the data after the last complete message (the start of the cut off
 * message, if any). Returns the number of messages.
 */
static long TrimPacket(const unsigned char * In, long InLen,
                       unsigned char * Out, long * OutLen,
                       Trunc ** Tr, long * TrCount, long * Tail)
{
    long p = 0, o = 0, Msgs = 0, TrAlloc = 0;

    *Tr      = NULL;
    *TrCount = 0;

    if(InLen >= PKT_HDR_SIZE)
    {
        memcpy(Out, In, PKT_HDR_SIZE);
        p = o = PKT_HDR_SIZE;

        while(InLen - p >= 2 && In[p] == 2 && In[p + 1] == 0)
        {
            long Start[4], Len[4];
            long q = p + MSG_HDR_SIZE;
            int i, n;

            Msgs++;

            if(InLen - p < MSG_HDR_SIZE)
            {
                break; /* cut off in the message header */
            }

            for(n = 0; n < 4; n++)
            {
                const unsigned char * z =
                    (const unsigned char *)memchr(In + q, 0, InLen - q);

                if(z == NULL)
                {
                    break;
                }

                Start[n] = q;
                Len[n]   = (long)(z - In) - q;
                q        = (long)(z - In) + 1;
            }

            memcpy(Out + o, In + p, MSG_HDR_SIZE);
            o += MSG_HDR_SIZE;

            for(i = 0; i < n; i++)
            {
                long l = Len[i];

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
                    (*TrCount)++;
                    l = FieldSize[i] - 1;
                }

                memcpy(Out + o, In + Start[i], l);
                o += l;
                Out[o++] = 0;
            }

            if(n < 4)
            {
                /* cut off: the unterminated rest is copied as is */
                memcpy(Out + o, In + q, InLen - q);
                *OutLen = o + (InLen - q);
                *Tail   = p;
                return Msgs;
            }

            p = q;
        }
    }

    /* the packet terminator or whatever follows the last message */
    memcpy(Out + o, In + p, InLen - p);
    *OutLen = o + (InLen - p);
    *Tail   = p;
    return Msgs;
}

static int ReadPkt(const char * Path, long Size, unsigned char * Buf)
{
    FILE * fh = fopen(Path, "rb");
    size_t n;
    int c;

    if(fh == NULL)
    {
        return 0;
    }

    n = fread(Buf, 1, (size_t)Size, fh);
    c = fgetc(fh);
    fclose(fh);
    return n == (size_t)Size && c == EOF;
}

static int WritePkt(const char * Path, const unsigned char * Buf, long Size)
{
    FILE * fh;
    int Ok;
    struct stat st;

    fh = fopen(Path, "wb");

    if(fh == NULL)
    {
        return 0;
    }

    Ok = fwrite(Buf, 1, (size_t)Size, fh) == (size_t)Size;
    Ok = (fflush(fh) == 0) && Ok;
    Ok = (fclose(fh) == 0) && Ok;
    return Ok && stat(Path, &st) == 0 && (long)st.st_size == Size;
}

/* Returns 0 on success (changed or not), 1 on error. */
static int ProcessPacket(const char * Path, const char * Tmp)
{
    struct stat st, st2;
    unsigned char * In;
    unsigned char * Out;
    Trunc * Tr = NULL;
    long OutLen, TrCount, Msgs, Tail, Rest, i;
    struct utimbuf ut;
    int Rc = 1;

    errno = 0;

    if(stat(Path, &st) != 0)
    {
        Log(LOG_ERR, "can't stat %s: %s, skipped", Path, strerror(errno));
        return 1;
    }

    In  = (unsigned char *)malloc(st.st_size ? (size_t)st.st_size : 1);
    Out = (unsigned char *)malloc(st.st_size ? (size_t)st.st_size : 1);

    if(In == NULL || Out == NULL)
    {
        Log(LOG_ERR, "not enough memory for %s (%ld bytes), skipped",
            Path, (long)st.st_size);
        goto done;
    }

    errno = 0;

    if(!ReadPkt(Path, (long)st.st_size, In))
    {
        Log(LOG_ERR, "can't read %s: %s, skipped", Path,
            errno ? strerror(errno) : "size changed while reading");
        goto done;
    }

    if(st.st_size < PKT_HDR_SIZE)
    {
        Log(LOG_ERR, "%s is not a packet: only %ld bytes, shorter than a packet "
            "header, skipped", Path, (long)st.st_size);
        Rc = 0;
        goto done;
    }

    Msgs = TrimPacket(In, (long)st.st_size, Out, &OutLen, &Tr, &TrCount, &Tail);
    Rest = (long)st.st_size - Tail;

    if(Rest == 2 && In[Tail] == 0 && In[Tail + 1] == 0)
    {
        /* a proper packet terminator */
    }
    else if(Msgs == 0)
    {
        Log(LOG_ERR, "%s is not a packet: no packed messages after the packet "
            "header (%ld bytes of unknown data at offset %ld), skipped", Path,
            Rest, Tail);
        Rc = 0;
        goto done;
    }
    else if(Rest >= 2 && In[Tail] == 2 && In[Tail + 1] == 0)
    {
        Log(LOG_WARN, "%s: message #%ld (offset %ld) is cut off by the end of "
            "the file, its unterminated part is kept as is", Path, Msgs, Tail);
    }
    else if(Rest == 0)
    {
        Log(LOG_WARN, "%s: no packet terminator, the file ends right after "
            "message #%ld", Path, Msgs);
    }
    else if(Rest == 1 && In[Tail] == 0)
    {
        Log(LOG_WARN, "%s: incomplete packet terminator after message #%ld "
            "(1 byte at offset %ld), kept as is", Path, Msgs, Tail);
    }
    else if(Rest > 2 && In[Tail] == 0 && In[Tail + 1] == 0)
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
        Log(LOG_INFO, "processed %s: %ld messages, nothing truncated", Path,
            Msgs);
        Rc = 0;
        goto done;
    }

    errno = 0;

    if(!WritePkt(Tmp, Out, OutLen))
    {
        Log(LOG_ERR, "can't write %s: %s, %s skipped", Tmp,
            errno ? strerror(errno) : "short write", Path);
        remove(Tmp);
        goto done;
    }

    /* the packet must not have been changed by somebody else meanwhile */
    if(stat(Path, &st2) != 0 || st2.st_size != st.st_size ||
       st2.st_mtime != st.st_mtime)
    {
        Log(LOG_ERR, "%s was changed by another program while processing, "
            "skipped", Path);
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
    utime(Path, &ut);

    for(i = 0; i < TrCount; i++)
    {
        Log(LOG_WARN, "truncated %s to %ld bytes (was %ld) in message #%ld "
            "in %s", FieldName[Tr[i].field], FieldSize[Tr[i].field] - 1,
            Tr[i].len, Tr[i].msg, Path);
    }

    Log(LOG_INFO, "processed %s: %ld messages, %ld fields truncated", Path,
        Msgs, TrCount);
    Rc = 0;

done:
    free(Tr);
    free(In);
    free(Out);
    return Rc;
}

/* ------------------------------------------------------------------ */
/* Directory scanning                                                 */

static int CmpStr(const void * a, const void * b)
{
    return strcmp(*(char * const *)a, *(char * const *)b);
}

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

static long FindName(char ** List, long Count, const char * Name)
{
    long i;

    for(i = 0; i < Count; i++)
    {
        if(StrICmp(List[i], Name) == 0)
        {
            return i;
        }
    }

    return -1;
}

/* Processes the current directory. Returns the number of errors. */
static int ProcessDir(void)
{
    char ** Pkts = NULL;
    char ** Tmps = NULL;
    long NPkts = 0, SPkts = 0, NTmps = 0, STmps = 0, i;
    int Errors = 0;
    DIR * d;
    struct dirent * de;

    errno = 0;
    d = opendir(".");

    if(d == NULL)
    {
        Log(LOG_ERR, "can't read the current directory: %s", strerror(errno));
        return 1;
    }

    while((de = readdir(d)) != NULL)
    {
        int Pkt = HasExt(de->d_name, ".pkt");

        if(Pkt || HasExt(de->d_name, ".tr$"))
        {
            struct stat st;
            /* a packet that can't be stat'ed is logged when processed */
            int Reg = stat(de->d_name, &st) != 0 || S_ISREG(st.st_mode);

            if(Reg && Pkt)
            {
                AddName(&Pkts, &NPkts, &SPkts, StrDup(de->d_name));
            }
            else if(Reg)
            {
                AddName(&Tmps, &NTmps, &STmps, StrDup(de->d_name));
            }
        }
    }

    closedir(d);

    if(NTmps > 1)
    {
        qsort(Tmps, NTmps, sizeof(char *), CmpStr);
    }

    /* temporary files left by an interrupted run */
    for(i = 0; i < NTmps; i++)
    {
        char * Tmp  = Tmps[i];
        char * Name = ChangeExt(Tmp, ".pkt");

        if(FindName(Pkts, NPkts, Name) >= 0)
        {
            if(remove(Tmp) == 0)
            {
                Log(LOG_WARN, "deleted incomplete temporary file %s", Tmp);
            }
            else
            {
                Log(LOG_ERR, "can't delete temporary file %s: %s", Tmp,
                    strerror(errno));
                Errors++;
            }

            free(Name);
        }
        else if(rename(Tmp, Name) == 0)
        {
            Log(LOG_WARN, "restored %s from temporary file %s", Name, Tmp);
            AddName(&Pkts, &NPkts, &SPkts, Name);
        }
        else
        {
            Log(LOG_ERR, "can't restore %s from temporary file %s: %s, "
                "retried on the next run", Name, Tmp, strerror(errno));
            Errors++;
            free(Name);
        }

        free(Tmp);
    }

    free(Tmps);

    if(NPkts > 1)
    {
        qsort(Pkts, NPkts, sizeof(char *), CmpStr);
    }

    for(i = 0; i < NPkts; i++)
    {
        char * Tmp = ChangeExt(Pkts[i], ".tr$");

        Errors += ProcessPacket(Pkts[i], Tmp);
        free(Tmp);
        free(Pkts[i]);
    }

    free(Pkts);
    return Errors;
}

/* ------------------------------------------------------------------ */

static void Usage(void)
{
    printf("PKT Sanitizer " VERSION " - truncate too long names and subjects "
           "in FTS-0001 packets\n\n"
           "Usage: " PROGNAME " [-c config]\n\n"
           "Processes all *.pkt files in the current directory. The default\n"
           "config is " CONFIGNAME " in the program directory.\n");
}

int main(int argc, char ** argv)
{
    char * Cfg = NULL;
    char * LogFile = NULL;
    int CfgRequired = 0;
    int Errors = 0;
    int i;

    for(i = 1; i < argc; i++)
    {
        if(strcmp(argv[i], "-c") == 0 && i + 1 < argc)
        {
            free(Cfg);
            Cfg = StrDup(argv[++i]);
            CfgRequired = 1;
        }
        else if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-?") == 0 ||
                strcmp(argv[i], "--help") == 0)
        {
            Usage();
            return 0;
        }
        else
        {
            fprintf(stderr, PROGNAME ": unknown argument '%s'\n", argv[i]);
            free(Cfg);
            return 1;
        }
    }

    if(Cfg == NULL)
    {
        Cfg = ConfigPath(argv[0]);
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

    Errors = ProcessDir();

    if(LogFh != NULL)
    {
        fclose(LogFh);
    }

    free(Cfg);
    free(LogFile);
    return Errors ? 1 : 0;
}

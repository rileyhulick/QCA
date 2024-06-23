// The Linux Kernel Cryptography API (a.k.a., kcapi) operates from userspace
// through the AF_NETLINK and AF_ALG socket protocols. Documentation for this
// is a bit thin in my opinion, and there are no well-defined conformance
// standards, but libkcapi (used by GnuTLS) and OpenSSL at least give some
// decent examples to cover the gaps -- and are presumably reliable, portable,
// and efficient.
//

// https://kernel.org/doc/html/latest/crypto/
// https://kernel.org/doc/html/latest/userspace-api/netlink/intro.html
// https://github.com/smuellerDD/libkcapi
// https://github.com/gnutls/gnutls/blob/master/lib/accelerated/afalg.c
// https://github.com/openssl/openssl/blob/master/engines/e_afalg.c
// https://github.com/thom311/libnl

#include "config-qca-linux.h"

#ifndef _GNU_SOURCE
# if USING_VM_SPLICE
#  define _GNU_SOURCE
# endif // USING_VM_SPLICE
#endif // _GNU_SOURCE

#include <QtGlobal>
// #ifdef Q_OS_LINUX

#include <QFlags>

// #include <cctype>   // std::isspace
#include <cerrno>
#include <cstdlib>
#include <cstring>  // std::memset, std::memcpy, std::strerror
#include <cstdint>
#include <unistd.h>

#include <algorithm>

#include <QtCrypto>
#include <QAtomicInteger>
#include <QMutex>
#include <QStringList>

#include <QMetaType>
#include <QObject>
#include <QVariantMap>

#include <QtDebug>

#include <sys/random.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#if USING_VM_SPLICE
#include <fcntl.h> // splice, vmsplice
#endif
#if USING_AF_NETLINK
#include <linux/netlink.h>
#include <linux/cryptouser.h>

#define KCAPI_GET_ATTR(x) (reinterpret_cast<struct ::nlattr *>((char *)(x) + NLA_ALIGN(sizeof(*x))));
#define KCAPI_ATTR_OK(x,len) (len >= (int)(sizeof(struct ::nlattr)) && x->nla_len >= sizeof(struct ::nlattr) && x->nla_len <= len)
#define KCAPI_ATTR_NEXT(x,attrlen) (attrlen -= NLA_ALIGN(x->nla_len), reinterpret_cast<struct ::nlattr *>((char *)(x) + NLA_ALIGN(x->nla_len)))
#define KCAPI_ATTR_DATA(x) ((void *)((char *)(x) + NLA_ALIGN(sizeof(struct ::nlattr))))
#endif

static const int g_page_size = qMax( static_cast<int>( ::sysconf(_SC_PAGESIZE)), 4096 );

static const struct { const char *k; const char *q; } g_hashNameMap[] = {
    // { .k = "md2",       .q = nullptr        },
    { .k = "md4",       .q = nullptr        },
    { .k = "md5",       .q = nullptr        },
    { .k = "rmd160",    .q = "ripemd160"    },
    // { .k = "sha0",      .q = nullptr        },
    { .k = "sha1",      .q = nullptr        },
    { .k = "sha224",    .q = nullptr        },
    { .k = "sha256",    .q = nullptr        },
    { .k = "sha384",    .q = nullptr        },
    { .k = "sha512",    .q = nullptr        },
    // { .k = "wp256",     .q = nullptr        },
    // { .k = "wp384",     .q = nullptr        },
    { .k = "wp512",     .q = "whirlpool"    },
};

static const struct { const char *k; const char *q; } g_cipherNameMap[] = {
    { .k = "aes",       .q = nullptr        },
    { .k = "blowfish",  .q = nullptr        },
    // { .k = "camelia",   .q = nullptr        },
    { .k = "cast5",     .q = nullptr        },
    { .k = "des",       .q = nullptr        },
    { .k = "des3_ede",  .q = "tripledes"    },
    // { .k = "twofish",   .q = nullptr        },
};

static const char * const g_cipherModes[] = {
    "cbc",
    "ccm",
    "cfb",
    "ctr",
    "ecb",
    "gcm",
    "ofb",
};

// #if !USING_AF_NETLINK
static const struct { uint b; uint d; } g_hashData[] = {
                 /* block size  digest size */
    // { /* md2 */     .b = 0,     .d = 0;     },
    { /* md4 */     .b = 64,    .d = 16     },
    { /* md5 */     .b = 64,    .d = 16     },
    { /* rmd160 */  .b = 64,    .d = 20     },
    // { /* sha0 */    .b = 0,     .d = 0      },
    { /* sha1 */    .b = 64,    .d = 20     },
    { /* sha224 */  .b = 64,    .d = 28     },
    { /* sha256 */  .b = 64,    .d = 32     },
    { /* sha384 */  .b = 128,   .d = 48     },
    { /* sha512 */  .b = 128,   .d = 64     },
    // { /* wp256 */   .b = 64,    .d = 32     },
    // { /* wp384 */   .b = 64,    .d = 48     },
    { /* wp512 */   .b = 64,    .d = 64     },
};

typedef uint (iv_size_t)[sizeof(g_cipherModes) / sizeof(*g_cipherModes)];
static const struct { uint b; uint k1; uint k2; iv_size_t i; } g_cipherData[] = {
                     /* block size  min key sz  max key sz  iv size */
                                                                /* cbc  ccm  cfb  ctr  ecb  gcm  ofb */
    { /* aes */         .b = 16,    .k1 = 16,   .k2 = 32,   .i = { 0,   0,   0,   0,   0,   0,   0   } },
    { /* blowfish */    .b = 0,     .k1 = 0,    .k2 = 0,    .i = { 0,   0,   0,   0,   0,   0,   0   } },
    // { /* camelia */     .b = 0,     .k1 = 0,    .k2 = 0,    .i = { 0,   0,   0,   0,   0,   0,   0   } },
    { /* cast5 */       .b = 0,     .k1 = 0,    .k2 = 0,    .i = { 0,   0,   0,   0,   0,   0,   0   } },
    { /* des */         .b = 0,     .k1 = 0,    .k2 = 0,    .i = { 0,   0,   0,   0,   0,   0,   0   } },
    { /* des3_ede */    .b = 0,     .k1 = 0,    .k2 = 0,    .i = { 0,   0,   0,   0,   0,   0,   0   } },
    // { /* twofish */     .b = 0,     .k1 = 0,    .k2 = 0,    .i = { 0,   0,   0,   0,   0,   0,   0   } },
};
// #endif // !USING_AF_NETLINK



inline QByteArray kcapi_cru_string_helper(const char *name)
{
    return QByteArray(name, std::find(name, name + CRYPTO_MAX_NAME, '\0') - name).trimmed();
}

struct kcapiDriverInfo
{
#if WITH_DRIVER_INTROSPECTION
    Q_GADGET
#endif
public:
    QByteArray name;
    QByteArray genericName;
    QByteArray moduleName;

    enum Type
    {
        NullType = 0,
        Hash,
        Random,
        SymmetricCipher,
        AsymmetricCipher,
        AEADCipher,
        KeyProtocol,
    };
#if WITH_DRIVER_INTROSPECTION
    Q_ENUM(Type);
#endif

    kcapiDriverInfo::Type type = NullType;

    QByteArray typeName;
    QStringList qcaNames;
    quint32 priority  = 0;
    uint blockSize    = 0;
    uint digestSize   = 0;
    uint minKeySize   = 0;
    uint maxKeySize   = 0;
    uint maxAuthSize  = 0;
    uint ivSize       = 0;
    uint seedSize     = 0;

    enum Flag
    {
        NullFlag            = 0x00,
        // NeedFallback        = 0x01, // CRYPTO_ALG_NEED_FALLBACK
        // TemplateInstance    = 0x02, // CRYPTO_ALG_INSTANCE
        OptionalKey         = 0x04, // CRYPTO_ALG_OPTIONAL_KEY

        // TopPriority         = 0x100, // internal
    };
    Q_DECLARE_FLAGS(Flags, Flag)
#if WITH_DRIVER_INTROSPECTION
    Q_FLAG(Flag)
#endif

    kcapiDriverInfo::Flags flags = NullFlag;

#if WITH_DRIVER_INTROSPECTION
    Q_PROPERTY(QByteArray name MEMBER name CONSTANT);
    Q_PROPERTY(QByteArray genericName MEMBER genericName CONSTANT);
    Q_PROPERTY(QByteArray moduleName MEMBER moduleName CONSTANT);
    Q_PROPERTY(Type type MEMBER type CONSTANT);
    Q_PROPERTY(QByteArray typeName MEMBER typeName CONSTANT);
    Q_PROPERTY(QStringList qcaNames MEMBER qcaNames CONSTANT);
    Q_PROPERTY(quint32 priority MEMBER priority CONSTANT);
    Q_PROPERTY(uint blockSize MEMBER blockSize CONSTANT);
    Q_PROPERTY(uint digestSize MEMBER digestSize CONSTANT);
    Q_PROPERTY(uint minKeySize MEMBER minKeySize CONSTANT);
    Q_PROPERTY(uint maxKeySize MEMBER maxKeySize CONSTANT);
    Q_PROPERTY(uint maxAuthSize MEMBER maxAuthSize CONSTANT);
    Q_PROPERTY(uint ivSize MEMBER ivSize CONSTANT);
    Q_PROPERTY(uint seedSize MEMBER seedSize CONSTANT);
    Q_PROPERTY(Flags flags MEMBER flags CONSTANT);

    Q_DECL_COLD_FUNCTION QVariantMap toVariantMap() const;
#endif

private:
    void initQCANames();
    friend class kcapiDriverDatabase;
};

void kcapiDriverInfo::initQCANames()
{
    Q_ASSERT(qcaNames.isEmpty());
    Q_ASSERT(!genericName.isEmpty());

    switch(type) {
    case kcapiDriverInfo::Hash:
        {
            typedef decltype((*g_hashNameMap)) kcapi_hash_name_t;
            auto cmp = [&] (const kcapi_hash_name_t &x) -> bool {
                    Q_ASSERT(x.k);
                    return x.k == genericName;
                };

            const auto *end = g_hashNameMap + (sizeof(g_hashNameMap) / sizeof(*g_hashNameMap));
            const auto *it = std::find_if(g_hashNameMap, end, cmp);

            if (it != end) {
                qcaNames.append(QString::fromLatin1(it->q ? it->q : it->k));
            }
        }
        break;

    case kcapiDriverInfo::SymmetricCipher:
        {
            // convert kcapi-style names "ctr(des3_ede)" to QCA-style names "tripledes-ctr"

            char buf[24];

            const char *modeSubstrBegin = genericName.constData();
            const char *modeSubstrEnd = std::find(genericName.constData(), genericName.constData() + genericName.size(), '(');

            const char *mode = nullptr;

            for (int i = 0; i < sizeof(g_cipherModes); ++i) {
                Q_ASSERT(g_cipherModes[i]);
                if (!std::strncmp(g_cipherModes[i], modeSubstrBegin, modeSubstrEnd - modeSubstrBegin)) {
                    mode = g_cipherModes[i];
                    break; // for
                }
            }

            if (!mode) {
                // warning?
                break; // switch
            }

            const char *cipherSubstrBegin = modeSubstrEnd;
            const char *cipherSubstrEnd = genericName.constData() + genericName.size();

            if (   cipherSubstrBegin == cipherSubstrEnd
                || *(cipherSubstrBegin++) != '(' || *(--cipherSubstrEnd) != ')' ) {
                // cipher name not found
                break; // switch
            }

            const char *kCipher = nullptr;
            const char *qCipher;

            for (int i = 0; i < sizeof(g_cipherNameMap); ++i) {
                Q_ASSERT(g_cipherNameMap[i].k);

                if (!std::strncmp(g_cipherNameMap[i].k, cipherSubstrBegin, cipherSubstrEnd - cipherSubstrBegin)) {
                    kCipher =  g_cipherNameMap[i].k;
                    qCipher = (g_cipherNameMap[i].q ? g_cipherNameMap[i].q : kCipher);
                    break; // for
                }
            }

            if (!kCipher) {
                // warning?
                break; // switch
            }

            if ( QLatin1String(kCipher) == QLatin1String("aes") /*|| kCipher == QLatin1String("camelia")*/ ) {
                for (int b : { 128, 192, 256 }) {
                    if (b < (int)(minKeySize * CHAR_BIT) || b > (int)(maxKeySize * CHAR_BIT)) {
                        // warning?
                        continue;
                    }
                    std::snprintf( buf, sizeof(buf), "%s%d-%s", kCipher, b, mode );
                    qcaNames.append(QString::fromLatin1(buf));
                }
            } else {
                std::snprintf( buf, sizeof(buf), "%s-%s", kCipher, mode );
                qcaNames.append(QString::fromLatin1(buf));
            }
        }
        break;

    case kcapiDriverInfo::Random:
        if ( genericName == "stdrng" ) {
            qcaNames.append(QStringLiteral("random"));
        }
        break;

    default:
        break;
    }

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    qcaNames.squeeze();
#endif
}

#if WITH_DRIVER_INTROSPECTION

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
Q_DECLARE_METATYPE(kcapiDriverInfo::Flags);
#endif

QVariantMap kcapiDriverInfo::toVariantMap() const
{
    return QVariantMap ({
        { QStringLiteral("blockSize"),      QVariant::fromValue(blockSize)      },
        { QStringLiteral("digestSize"),     QVariant::fromValue(digestSize)     },
        { QStringLiteral("flags"),          QVariant::fromValue(flags)          },
        { QStringLiteral("genericName"),    QVariant::fromValue(genericName)    },
        { QStringLiteral("ivSize"),         QVariant::fromValue(ivSize)         },
        { QStringLiteral("maxAuthSize"),    QVariant::fromValue(maxAuthSize)    },
        { QStringLiteral("maxKeySize"),     QVariant::fromValue(maxKeySize)     },
        { QStringLiteral("minKeySize"),     QVariant::fromValue(minKeySize)     },
        { QStringLiteral("moduleName"),     QVariant::fromValue(moduleName)     },
        { QStringLiteral("name"),           QVariant::fromValue(name)           },
        { QStringLiteral("priority"),       QVariant::fromValue(priority)       },
        { QStringLiteral("qcaNames"),       QVariant::fromValue(qcaNames)       },
        { QStringLiteral("seedSize"),       QVariant::fromValue(seedSize)       },
        { QStringLiteral("type"),           QVariant::fromValue(type)           },
        { QStringLiteral("typeName"),       QVariant::fromValue(typeName)       },
    });
}

#endif

Q_DECLARE_OPERATORS_FOR_FLAGS(kcapiDriverInfo::Flags);

class kcapiDriverDatabase
{
public:
    kcapiDriverDatabase() = default;
    ~kcapiDriverDatabase()
    {
        qDeleteAll(_drivers);
    }

    int reload()
    {
        const QMutexLocker _(&_mutex);
        return loadDrivers_p();
    }

    QStringList names()
    {
        const QMutexLocker _(&_mutex);

        if (!_isLoaded && (loadDrivers_p() != 0)) {
            qWarning("qca-linux encountered an issue loading available algorithms.");
        }
        return _names;
    }

    QList<kcapiDriverInfo> drivers()
    {
        const QMutexLocker _(&_mutex);
        if (!_isLoaded && (loadDrivers_p() != 0)) {
            qWarning("qca-linux encountered an issue loading available algorithms.");
        }

        QList<kcapiDriverInfo> result;
        result.reserve(_drivers.size());

        for (kcapiDriverInfo *driver : _drivers) {
            result.append(*driver);
        }

        return result;
    }

    bool get(const QString& name, kcapiDriverInfo& out)
    {
        const QMutexLocker _(&_mutex);
        if (!_isLoaded && (loadDrivers_p() != 0)) {
            qWarning("qca-linux encountered an issue loading available algorithms.");
        }

        const auto find = _index.constFind(name);
        if (find != _index.constEnd()) {
            out = **find;
            return true;
        }

        return false;
    }

private:
    int loadDrivers_p();

    QList<kcapiDriverInfo *>          _drivers;
    QStringList                       _names;
    QHash<QString, kcapiDriverInfo *> _index;
    bool _isLoaded = false;

    QMutex _mutex;
};

int kcapiDriverDatabase::loadDrivers_p()
{
    alignas(NLMSG_ALIGNTO) char send_buf[ NLMSG_LENGTH(sizeof(struct ::crypto_user_alg)) ];

    struct ::sockaddr_nl nl_addr;
    struct ::iovec send_iov;
    struct ::msghdr send_msg;
    struct ::nlmsghdr *send_nlh;

    static auto nlmsg_seq = QAtomicInteger<quint32>(0U);

    int nl_sock;

    if ((nl_sock = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_CRYPTO)) == -1) {
        const int errno_ = errno;
        qWarning("qca-linux could not open AF_NETLINK socket: %s", ::strerror(errno_));
        return errno_;
    }

    std::memset(&nl_addr, '\0', sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;
    if( ::bind(nl_sock, reinterpret_cast<struct ::sockaddr *>(&nl_addr), sizeof(nl_addr)) == -1 ) {
        int errno_ = errno;
        qWarning("qca-linux could not bind AF_NETLINK socket: %s", ::strerror(errno_));
        if(Q_UNLIKELY( ::close(nl_sock) == -1 && (errno != EINTR) )) {
            qWarning("qca-linux encountered an unexpected error closing AF_NETLINK socket.");
        }
        return errno_;
    }

    std::memset(&send_buf, '\0', sizeof(send_buf));
    send_nlh = reinterpret_cast<struct ::nlmsghdr *>(send_buf);
    send_nlh->nlmsg_type    = CRYPTO_MSG_GETALG;
    send_nlh->nlmsg_flags   = NLM_F_REQUEST | NLM_F_DUMP;
    send_nlh->nlmsg_len     = NLMSG_LENGTH(sizeof(struct ::crypto_user_alg));
    send_nlh->nlmsg_seq     = nlmsg_seq++;

    std::memset(&send_iov, '\0', sizeof(send_iov));
    send_iov.iov_base       = (void *)(send_nlh);
    send_iov.iov_len        = send_nlh->nlmsg_len;

    std::memset(&send_msg, '\0', sizeof(send_msg));
    send_msg.msg_name       = (void *)(&nl_addr);
    send_msg.msg_namelen    = sizeof(nl_addr);
    send_msg.msg_iov        = &send_iov;
    send_msg.msg_iovlen     = 1;

    if ( ::sendmsg(nl_sock, &send_msg, 0) == -1 ) {
        const int errno_ = errno;
        qWarning("qca-linux could not send message to kernel: %s", ::strerror(errno_));

        if(Q_UNLIKELY( ::close(nl_sock) == -1 && (errno != EINTR) )) {
            qWarning("qca-linux encountered an unexpected error closing AF_NETLINK socket.");
        }
        return errno_;
    }

    const std::size_t recv_buf_len = 65536UL; // 64KiB
    // This number comes from crypto/crypto_user_base.c in the kernel where it
    // appears to be the minimum buffer size to guarantee that this particular
    // dump is not truncated.

    void *recv_buf;
    if ( !(recv_buf = std::malloc(recv_buf_len)) ) {
        qWarning("qca-linux could not allocate a buffer to receive data from kernel.");
        if(Q_UNLIKELY( ::close(nl_sock) == -1 && (errno != EINTR) )) {
            qWarning("qca-linux encountered an unexpected error closing AF_NETLINK socket.");
        }
        return ENOMEM;

        // TODO: fallback to static info?
    }

    _isLoaded = false;

    qDeleteAll(_drivers);
    _drivers.clear();
    _names.clear();
    _index.clear();

    std::unique_ptr<kcapiDriverInfo> driver;

    int ret = 0;
    for (;;) {
        int recv_len = ::recv(nl_sock, recv_buf, recv_buf_len, 0);
        if (recv_len == -1) {
            const int errno_ = errno;
            if (errno_ == EINTR) {
                continue;
            }

            qWarning("qca-linux could not receive AF_NETLINK message from kernel: %s", ::strerror(errno_));
            ret = errno_;
            goto recv_done;
        }

        auto *recv_nlh = reinterpret_cast<struct ::nlmsghdr *>(recv_buf);

        for (; NLMSG_OK(recv_nlh, recv_len); recv_nlh = NLMSG_NEXT(recv_nlh, recv_len)) {
            if (recv_nlh->nlmsg_type == NLMSG_DONE) {
                goto recv_done;
            }

            if (recv_nlh->nlmsg_type == NLMSG_ERROR) {
                auto *nlerr = reinterpret_cast<struct ::nlmsgerr *>(NLMSG_DATA(recv_nlh));
                const int errno_ = nlerr->error;
                qWarning("qca-linux received an AF_NETLINK error from the kernel: %s", ::strerror(errno_));

                int err_attrs_len = recv_nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct ::nlmsgerr));
                struct ::nlattr *err_nla = KCAPI_GET_ATTR(nlerr);

                for (; KCAPI_ATTR_OK(err_nla, err_attrs_len); err_nla = KCAPI_ATTR_NEXT(err_nla, err_attrs_len)) {
                    if (err_nla->nla_type == NLMSGERR_ATTR_MSG) {
                        qWarning(
                            "qca-linux received an AF_NETLINK error message from the kernel: %s",
                            reinterpret_cast<const char*>(KCAPI_ATTR_DATA(err_nla))
                        );
                    }
                }

                ret = errno_;
                goto recv_done;
            }

            if (Q_UNLIKELY( recv_nlh->nlmsg_type != CRYPTO_MSG_GETALG )) {
                qWarning("qca-linux received unexpected nlmsg_type from the kernel.");
                ret = EAGAIN;
                goto recv_done;
            }

            if (Q_UNLIKELY( !(recv_nlh->nlmsg_flags & NLM_F_MULTI) || (recv_nlh->nlmsg_flags & NLM_F_DUMP_INTR) )) {
                qWarning("qca-linux received unexpected nlmsg_flags from the kernel.");
                ret = EAGAIN;
                goto recv_done;
            }

            auto *recv_cru = reinterpret_cast<struct ::crypto_user_alg *>(NLMSG_DATA(recv_nlh));
            if ( recv_cru->cru_flags & 0x22000 ) {
                // internal or otherwise not available as-is to userspace
                continue;
            }

            // we don't keep every driver we make, so if we still have one from
            // a previous loop then we'll just erase it and use it again to save
            // a reallocation

            if (driver) {
                (*driver) = kcapiDriverInfo();
            } else {
                driver.reset(new kcapiDriverInfo);
            }

//             if (recv_cru->cru_flags & 0x0100) {
//                 driver.flags |= kcapiDriverInfo::NeedFallback;
//             }
//
//             // if (recv_cru->cru_flags & 0x0800) {
//             //     driver.flags |= kcapiDriverInfo::TemplateInstance;
//             // }

            if (recv_cru->cru_flags & 0x4000) {
                driver->flags |= kcapiDriverInfo::OptionalKey;
            }

            bool unsupported_driver = false;

            switch(recv_cru->cru_flags & 0x0f) {
            case 0x01: // CRYPTO_ALG_TYPE_CIPHER
            case 0x02: // CRYPTO_ALG_TYPE_COMPRESS
            case 0x0a: // CRYPTO_ALG_TYPE_ACOMPRESS
            case 0x0b: // CRYPTO_ALG_TYPE_SCOMPRESS
                unsupported_driver = true;
                break;

            case 0x03: // CRYPTO_ALG_TYPE_AEAD
                driver->type = kcapiDriverInfo::AEADCipher;
                break;

            case 0x05: // CRYPTO_ALG_TYPE_SKCIPHER
                driver->type = kcapiDriverInfo::SymmetricCipher;
                break;

            case 0x08: // CRYPTO_ALG_TYPE_KPP
                driver->type = kcapiDriverInfo::KeyProtocol;
                break;

            case 0x0c: // CRYPTO_ALG_TYPE_RNG
                driver->type = kcapiDriverInfo::Random;
                break;

            case 0x0d: // CRYPTO_ALG_TYPE_AKCIPHER;
                driver->type = kcapiDriverInfo::AsymmetricCipher;
                break;

            case 0x0e: // CRYPTO_ALG_TYPE_SHASH
            case 0x0f: // CRYPTO_ALG_TYPE_AHASH
                driver->type = kcapiDriverInfo::Hash;
                break;

            default:
                if (recv_cru->cru_flags & 0x0e /* CRYPTO_ALG_TYPE_HASH_MASK */ ) {
                    driver->type = kcapiDriverInfo::Hash;
                    break;
                }
            }

            if (unsupported_driver) {
                continue;
            }

            driver->name        = kcapi_cru_string_helper(recv_cru->cru_driver_name);
            driver->genericName = kcapi_cru_string_helper(recv_cru->cru_name);

            if (driver->name.isEmpty() || driver->genericName.isEmpty()) {
                qWarning("qca-linux encountered a driver with an empty or invalid name.");
                continue;
            }

            driver->moduleName  = kcapi_cru_string_helper(recv_cru->cru_module_name);

            bool priorityAttrFound  = false;
            bool typeAttrFound      = false;

            struct ::nlattr *cru_nla = KCAPI_GET_ATTR(recv_cru);

            int cru_attrs_len = recv_nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct ::crypto_user_alg));
            for(; KCAPI_ATTR_OK(cru_nla, cru_attrs_len); cru_nla = KCAPI_ATTR_NEXT(cru_nla, cru_attrs_len)) {
                switch(cru_nla->nla_type) {
                case CRYPTOCFGA_PRIORITY_VAL:
                    if (priorityAttrFound) {
                        // warning
                    } else {
                        driver->priority = *reinterpret_cast<quint32 *>(KCAPI_ATTR_DATA(cru_nla));
                        priorityAttrFound = true;
                    }
                    break; // switch

                case CRYPTOCFGA_REPORT_HASH:
                    if (typeAttrFound) {
                        // warning
                    } else {
                        auto *report = reinterpret_cast<struct ::crypto_report_hash *>(KCAPI_ATTR_DATA(cru_nla));

                        if(driver->type == kcapiDriverInfo::NullType) {
                            // warning
                            driver->type = kcapiDriverInfo::Hash;
                        } else
                        if (driver->type != kcapiDriverInfo::Hash) {
                            // warning
                            break; // switch
                        }

                        driver->typeName    = kcapi_cru_string_helper(report->type);
                        driver->blockSize   = report->blocksize;
                        driver->digestSize  = report->digestsize;

                        typeAttrFound = true;
                    }
                    break; // switch

                case CRYPTOCFGA_REPORT_BLKCIPHER:
                    if (typeAttrFound) {
                        // warning
                    } else {
                        auto *report = reinterpret_cast<struct ::crypto_report_blkcipher *>(KCAPI_ATTR_DATA(cru_nla));

                        if(driver->type == kcapiDriverInfo::NullType) {
                            // warning
                            driver->type = kcapiDriverInfo::SymmetricCipher;
                        } else
                        if (driver->type !=kcapiDriverInfo::SymmetricCipher) {
                            // warning
                            break; // switch
                        }

                        driver->typeName    = kcapi_cru_string_helper(report->type);
                        driver->blockSize   = report->blocksize;
                        driver->minKeySize  = report->min_keysize;
                        driver->maxKeySize  = report->max_keysize;
                        driver->ivSize      = report->ivsize;

                        typeAttrFound = true;
                    }
                    break; // switch

                case CRYPTOCFGA_REPORT_AEAD:
                    if (typeAttrFound) {
                        // warning
                    } else {
                        auto *report = reinterpret_cast<struct ::crypto_report_aead *>(KCAPI_ATTR_DATA(cru_nla));

                        if(driver->type == kcapiDriverInfo::NullType) {
                            //warning
                            driver->type = kcapiDriverInfo::AEADCipher;
                        } else
                        if (driver->type != kcapiDriverInfo::AEADCipher) {
                            // warning
                            break; // switch
                        }

                        driver->typeName    = kcapi_cru_string_helper(report->type);
                        driver->blockSize   = report->blocksize;
                        driver->maxAuthSize = report->maxauthsize;
                        driver->ivSize      = report->ivsize;

                        typeAttrFound = true;
                    }
                    break; // switch

                case CRYPTOCFGA_REPORT_RNG:
                    if (typeAttrFound) {
                        // warning
                    } else {
                        auto *report = reinterpret_cast<struct ::crypto_report_rng *>(KCAPI_ATTR_DATA(cru_nla));

                        if(driver->type == kcapiDriverInfo::NullType) {
                            driver->type = kcapiDriverInfo::Random;
                            //warning
                        } else
                        if (driver->type != kcapiDriverInfo::Random) {
                            // warning
                            break; // switch
                        }

                        driver->typeName    = kcapi_cru_string_helper(report->type);
                        driver->seedSize    = report->seedsize;
                        if (!report->seedsize) {
                            driver->flags |= kcapiDriverInfo::OptionalKey;
                        }

                        typeAttrFound = true;
                    }
                    break; // switch

                case CRYPTOCFGA_REPORT_AKCIPHER:
                    if (typeAttrFound) {
                        // warning
                    } else {
                        auto *report = reinterpret_cast<struct ::crypto_report_akcipher *>(KCAPI_ATTR_DATA(cru_nla));
                        if (driver->type == kcapiDriverInfo::NullType) {
                            // warning
                            driver->type = kcapiDriverInfo::AsymmetricCipher;
                        } else
                        if (driver->type != kcapiDriverInfo::AsymmetricCipher) {
                            // warning
                            break; // switch
                        }

                        driver->typeName    = kcapi_cru_string_helper(report->type);
                        typeAttrFound       = true;
                    }
                    break; // switch

                case CRYPTOCFGA_REPORT_KPP:
                    if (typeAttrFound) {
                        // warning
                    } else {
                        auto *report = reinterpret_cast<struct ::crypto_report_kpp *>(KCAPI_ATTR_DATA(cru_nla));
                        if (driver->type == kcapiDriverInfo::NullType) {
                            // warning
                            driver->type = kcapiDriverInfo::KeyProtocol;
                        } else
                        if (driver->type != kcapiDriverInfo::KeyProtocol) {
                            // warning
                            break; // switch
                        }

                        driver->typeName    = kcapi_cru_string_helper(report->type);
                        typeAttrFound       = true;
                    }
                    break; // switch

                default:
                    if (cru_nla->nla_type > CRYPTOCFGA_MAX) {
                        // warning
                    }
                }
            }

            if (Q_UNLIKELY( driver->type == kcapiDriverInfo::NullType )) {
                qWarning("qca-linux could not identify the type of driver \"%s\"", driver->name.data());
                continue;
            }

            if (Q_UNLIKELY( !typeAttrFound || !priorityAttrFound )) {
                qWarning("qca-linux could not find one or more attributes for the driver \"%s\"", driver->name.data());
                continue;
            }

            if (Q_UNLIKELY( driver->name.startsWith("__") )) {
                // warning
            }

            _drivers.append(driver.get());

            driver->initQCANames();
            for (QString name : driver->qcaNames) {
                auto driverFind = _index.find(name);
                if (driverFind == _index.end()) {
                    _index.insert(name, driver.get());
                    _names.append(name);
                } else
                if (driver->priority > (*driverFind)->priority) {
                    (*driverFind) = driver.get();
                }
            }

            {
                QString driverName = QString::fromLatin1(driver->name);
                if (_index.contains(driverName)) {
                    // warning
                } else {
                    _index.insert(driverName, driver.get());
                    _names.append(driverName);
                }
            }

            driver.release();
        }
    }
    Q_UNREACHABLE();

recv_done:
    if(Q_UNLIKELY( ::close(nl_sock) == -1 && (errno != EINTR) )) {
        qWarning("qca-linux encountered an unexpected error closing AF_NETLINK socket.");
    }
    std::free(recv_buf);

    if (!_drivers.isEmpty()) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        _drivers.squeeze();
        _names.squeeze();
        _index.squeeze();
#endif
        _names.sort();
        _isLoaded = true;
    }

    return ret;
}

Q_GLOBAL_STATIC(kcapiDriverDatabase, g_driverDatabase);

struct kcapiAlgorithmHandle
{
    explicit kcapiAlgorithmHandle(const kcapiDriverInfo &driver_)
        : driver(driver_)
    {
    }

    kcapiAlgorithmHandle(const kcapiAlgorithmHandle&) = delete;

    ~kcapiAlgorithmHandle()
    {
        if (op_sock > 0 && ::close(op_sock) == -1 ) {
            qWarning("qca-linux failed to close AF_ALG/TFM socket.");
        }
    }

    int init();

    void deinit()
    {
        if (op_sock > 0 && ::close(op_sock) == -1 ) {
            qWarning("qca-linux failed to close AF_ALG/TFM socket.");
        }
        op_sock = 0;
    }

    kcapiDriverInfo driver;
    int op_sock = 0;
    const QCA::SecureArray *key = nullptr;
};

int kcapiAlgorithmHandle::init()
{
    // Q_ASSERT(!driver.name.isEmpty());

    struct ::sockaddr_alg alg_addr;
    std::memset(&alg_addr, '\0', sizeof(alg_addr));

    alg_addr.salg_family = AF_ALG;

    if (!driver.name.isEmpty()) {
        std::strncpy((char *)(alg_addr.salg_name), driver.name.constData(), sizeof(alg_addr.salg_name) - 1);
    } else
    if (!driver.genericName.isEmpty()) {
        std::strncpy((char *)(alg_addr.salg_name), driver.genericName.constData(), sizeof(alg_addr.salg_name) - 1);
    } else {
        // warning
        return EINVAL;
    }

    {
        const char *salg_type_;

        switch(driver.type) {
        case kcapiDriverInfo::Hash:
            salg_type_ = "hash";
            break;
        case kcapiDriverInfo::SymmetricCipher:
            salg_type_ = "skcipher";
            break;
        case kcapiDriverInfo::Random:
            salg_type_ = "rng";
            break;

        default:
            op_sock = -1;

            qWarning("qca-linux does not support AF_ALG connection for kcapiDriverInfo::Type %d.", driver.type);
            return ENOTSUP;
        }

        std::strncpy((char *)(alg_addr.salg_type), salg_type_, sizeof(alg_addr.salg_type));
    }

    int alg_sock;
    if ( (alg_sock = ::socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1 ) {
        const int errno_ = errno;
        op_sock = -1;

        qWarning("qca-linux could not open AF_ALG socket: %s", ::strerror(errno_));
        return errno_;
    }

    if ( ::bind(alg_sock, reinterpret_cast<struct sockaddr *>((void *)(&alg_addr)), sizeof(alg_addr)) == -1 ) {
        const int errno_ = errno;
        op_sock = -1;

        qWarning("qca-linux could not bind AF_ALG socket: %s", ::strerror(errno_));
        if ( ::close(alg_sock) == -1 && (errno != EINTR)) {
            qWarning("qca-linux encountered unexpected error closing AF_ALG socket.");
        }
        return errno_;
    }

    if (key) {
        if (driver.type == kcapiDriverInfo::Random && key->size() != (int)(driver.seedSize)) {
            // warning
        } else
        if (key->size() < (int)(driver.minKeySize)) {
            // warning
        } else
        if (key->size() > (int)(driver.maxKeySize)) {
            // warning
        }

        if ( ::setsockopt(alg_sock, SOL_ALG, ALG_SET_KEY, key->data(), key->size()) == -1 ) {
            const int errno_ = errno;
            op_sock = -1;

            if (driver.type == kcapiDriverInfo::Random) {
                qWarning("qca-linux encountered an error initializing AF_ALG random seed: %s", ::strerror(errno_));
            } else {
                qWarning("qca-linux encountered an error initializing AF_ALG cipher key: %s", ::strerror(errno_));
            }

            if ( ::close(alg_sock) == -1 ) {
                qWarning("qca-linux failed to close AF_ALG socket.");
            }
            return errno_;
        }
    }

    if ( (op_sock = ::accept(alg_sock, nullptr, nullptr)) == -1 ) {
        const int errno_ = errno;

        qWarning("qca-linux could not accept AF_ALG/TFM socket: %s", ::strerror(errno_));
        if ( ::close(alg_sock) == -1 ) {
            qWarning("qca-linux failed to close AF_ALG socket.");
        }
        return errno_;
    }

    if ( ::close(alg_sock) == -1 ) {
        qWarning("qca-linux failed to close AF_ALG socket.");
    }

    return 0;
}

#if USING_VM_SPLICE
struct kcapiSpliceHelper
{
    int send(int flags = 0)
    {
        return splice_p(true, flags);
    }

    int recv(int flags = 0)
    {
        return splice_p(false, flags);
    }

    int op_sock = -1;
    const QCA::MemoryRegion *in = nullptr;
    QCA::MemoryRegion *out = nullptr;

    int errno_ = 0;

private:
    int splice_p(bool sending, int flags);
};

int kcapiSpliceHelper::splice_p(bool sending, int flags)
{
    Q_ASSERT( op_sock > 0 );

    int pipes[2];
    if ( ::pipe(pipes) == -1) {
        errno_ = errno;
        // warning
        return -1;
    }

    struct iovec iov;
    std::memset(&iov, '\0', sizeof(iov));

    if (sending) {
        Q_ASSERT(in && !in->isEmpty());
        iov.iov_base = const_cast<char *>(in->constData());
        iov.iov_len = in->size();
    } else {
        Q_ASSERT(out && !out->isEmpty());
        iov.iov_base = const_cast<char *>(out->constData());
        iov.iov_len = out->size();
    }

    int size_remaining = iov.iov_len;
    int chunk_size;
    do {
        chunk_size = qMin(size_remaining, g_page_size * 16);

        if( ::vmsplice(pipes[sending ? 1 : 0], &iov, 1, SPLICE_F_GIFT) == -1 ) {
            errno_ = errno;
            //warning
            break;
        }
        if( ::splice(pipes[sending ? 0 : 1], nullptr, op_sock, nullptr, chunk_size, SPLICE_F_MOVE | flags) == -1 ) {
            errno_ = errno;
            // warning
            break;
        }

        reinterpret_cast<char *&>(iov.iov_base) += chunk_size;
        iov.iov_len = chunk_size;

    } while ((size_remaining -= chunk_size) > 0);

    if( ::close(pipes[0]) == -1 || ::close(pipes[1]) == -1 ) {
        qWarning("qca-linux failed to close splice pipe.");
    }

    return (errno_ == 0) ? 0 : -1;
}
#endif // USING_VM_SPLICE

class kcapiHashContext final : public QCA::HashContext
{
    Q_OBJECT
public:
    kcapiHashContext(QCA::Provider *p, const QString &type, const kcapiDriverInfo &driver)
        : QCA::HashContext(p, type), _alg(driver)
    {
    }

    ~kcapiHashContext() override = default;

    QCA::Provider::Context *clone() const override
    {
        return new kcapiHashContext(provider(), type(), _alg.driver);
    }

    void clear() override
    {
        if(_alg.op_sock == 0) {
            return;
        } else
        if (_alg.op_sock < 0 ) {
            // warning
        }

        _alg.deinit();
    }

    QCA::MemoryRegion final() override;
    void update(const QCA::MemoryRegion &a) override;

private:
    kcapiAlgorithmHandle _alg;
};

QCA::MemoryRegion kcapiHashContext::final()
{
    if (_alg.op_sock < 0 || (_alg.op_sock == 0 && _alg.init() != 0)) {
        // warning
        return QCA::SecureArray();
    }

    QCA::SecureArray a(_alg.driver.digestSize, '\0');

    struct iovec recv_iov;
    struct msghdr recv_msg;

    std::memset(&recv_iov, '\0', sizeof(recv_iov));
    recv_iov.iov_base = a.data();
    recv_iov.iov_len = a.size();

    std::memset(&recv_msg, '\0', sizeof(recv_msg));
    recv_msg.msg_iov = &recv_iov;
    recv_msg.msg_iovlen = 1;

    int result_len = 0;

    for(;;) {

        int recv_len = ::recvmsg(_alg.op_sock, &recv_msg, 0);
        if (recv_len < 0) {
            const int errno_ = errno;
            qWarning("qca-linux encountered an error while reading hash output from the kernel: %s", ::strerror(errno_));

            return QCA::MemoryRegion();
        }

        result_len += recv_len;
        if (Q_UNLIKELY(recv_msg.msg_flags & MSG_TRUNC)) {
            const int chunk_size = 256;
            int oldSize = a.size();
            a.resize(a.size() + (chunk_size - a.size() % chunk_size));

            recv_iov.iov_base = a.data() + oldSize;
            recv_iov.iov_len = a.size() - oldSize;
            continue;
        }

        break;
    }

    a.resize(result_len);
    return a;
}

void kcapiHashContext::update(const QCA::MemoryRegion &a)
{
    if (_alg.op_sock < 0 || (_alg.op_sock == 0 && _alg.init() != 0)) {
        // warning
        return;
    }

    if (a.isEmpty()) {
        return;
    }

    kcapiSpliceHelper splice;
    splice.op_sock = _alg.op_sock;
    splice.in = &a;
    splice.out = nullptr;

    if ( splice.send(SPLICE_F_MORE) == -1 ) {
        qWarning("qca-linux encountered an error sending hash input to the kernel: %s", ::strerror(splice.errno_));
    }
}

class kcapiRandomContext final : public QCA::RandomContext
{
    Q_OBJECT
public:
    kcapiRandomContext(QCA::Provider *p, const kcapiDriverInfo &driver)
        : RandomContext(p), _alg(driver)
    {
    }

    ~kcapiRandomContext() override = default;

    QCA::Provider::Context *clone() const override
    {
        return new kcapiRandomContext(provider(), _alg.driver);
    }

    QCA::SecureArray nextBytes(int size) override;

private:
    int init_p();
    kcapiAlgorithmHandle _alg;
};

int kcapiRandomContext::init_p()
{
    if (_alg.driver.flags & kcapiDriverInfo::OptionalKey) {
        // skip seed population
        return _alg.init();
    }

    Q_ASSERT(_alg.driver.seedSize);

    int grnd_flags  = GRND_NONBLOCK;
    if (_alg.driver.seedSize <= 512) {
        // 512 bytes is the maximum entropy pool for /dev/random
        grnd_flags |= GRND_RANDOM;
    }

    QCA::SecureArray seed(_alg.driver.seedSize, '\0');

    char *grnd_buf  = seed.data();
    int grnd_buflen = seed.size();

    for(;;) {
        int grnd_len = ::getrandom( grnd_buf, grnd_buflen, grnd_flags );

        if (grnd_len == -1) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN) {
                if (grnd_flags & GRND_RANDOM) {
                    // not enough entropy currently available,
                    // try again using /dev/urandom
                    grnd_flags &= ~GRND_RANDOM;
                    continue;
                } else {
                    qWarning("qca-linux could not read rng seed because /dev/urandom is not initialized.");
                    return EAGAIN;
                }
            }

            const int errno_ = errno;
            qWarning("qca-linux encountered an unexpected error while initializing rng seed: %s", ::strerror(errno_));
            return errno_;
        }

        if (Q_UNLIKELY(grnd_len < grnd_buflen)) {
            // very unlikely: /dev/urandom is guaranteed to return for requests
            // of up to 256 bytes and the main rng driver ansi-cprng uses 48

            grnd_buf    += grnd_len;
            grnd_buflen -= grnd_len;
            continue;
        }

        break;
    }

    if (grnd_flags & GRND_RANDOM) {
        qInfo("qca-linux initialized rng seed with %d bytes from /dev/random", seed.size());
    } else {
        qInfo("qca-linux initialized rng seed with %d bytes from /dev/urandom", seed.size());
    }

    _alg.key = &seed;
    int ret = _alg.init();
    _alg.key = nullptr;

    seed.clear();

    return ret;
}

QCA::SecureArray kcapiRandomContext::nextBytes(int size)
{
    if (_alg.op_sock < 0 || (_alg.op_sock == 0 && init_p() != 0)) {
        // warning
        return QCA::SecureArray();
    }
    
    QCA::SecureArray a(size, '\0');
    
    int chunk_size;
    char *read_dest = a.data();
    
    do {
        const int max_chunk_size = 128; // where does this number come from?
        
        if ( (chunk_size = ::read(_alg.op_sock, read_dest, qMin(size, max_chunk_size))) == -1 ) {
            const int errno_ = errno;
            qWarning("qca-linux encountered an error while reading rng output (errno %d) %s",
                     errno_, ::strerror(errno_));
            break;
        }
        
        read_dest += chunk_size;
        
    } while (( size -= chunk_size ) > 0);
    
    Q_ASSERT(read_dest == a.data() + a.size());
    return a;
}

class kcapiCipherContext final : public QCA::CipherContext
{
    Q_OBJECT
public:
    kcapiCipherContext(QCA::Provider *p, const QString &type, const kcapiDriverInfo &driver)
        : QCA::CipherContext(p, type), _alg(driver)
    {
    }
    
    ~kcapiCipherContext() override = default;
    
    QCA::Provider::Context *clone() const override
    {
        return new kcapiHashContext(provider(), type(), _alg.driver);
    }
    
    int blockSize() const override
    {
        return _alg.driver.blockSize;
    }
    
    QCA::KeyLength keyLength() const override
    {
        return QCA::KeyLength(_alg.driver.minKeySize, _alg.driver.maxKeySize, 1);
    }
    
    QCA::AuthTag tag() const override
    {
        return QCA::AuthTag(); // TODO
    }
    
    void setup(QCA::Direction dir, const QCA::SymmetricKey &key,    
               const QCA::InitializationVector &iv, const QCA::AuthTag &tag) override;
    bool update(const QCA::SecureArray &in, QCA::SecureArray *out) override;
    bool final(QCA::SecureArray *out) override;
    
private:
    QCA::SymmetricKey _key;
    kcapiAlgorithmHandle _alg;
};

void kcapiCipherContext::setup(QCA::Direction dir, 
                               const QCA::SymmetricKey &key,    
                               const QCA::InitializationVector &iv, 
                               const QCA::AuthTag &tag)
{
    Q_UNUSED(tag);
    alignas(std::max_align_t) char cmsg_buf[1024];
    
    if (_alg.op_sock != 0) {
        // warning
        _alg.deinit();
    }

    _key = key;
    _alg.key = &_key;
    
    if (_alg.init() != 0) {
        _alg.key = nullptr;
        _key.clear();
        // warning
        return;
    }
    
    std::size_t cmsg_len = CMSG_SPACE(sizeof(quint32)) + CMSG_SPACE(sizeof(struct ::af_alg_iv) + iv.size());
    
    void* cmsg_data;
    if ( cmsg_len <= sizeof(cmsg_buf) ) {
        std::memset(&cmsg_buf, '\0', cmsg_len);
        cmsg_data = &cmsg_buf;
    } else
    if ( !(cmsg_data = std::calloc(1, cmsg_len)) ) {
        // warning
        _alg.deinit();
        return;
    }
    
    struct ::msghdr msg;
    std::memset(&msg, '\0', sizeof(msg));
    msg.msg_control = cmsg_data;
    msg.msg_controllen = cmsg_len;
    
    struct ::cmsghdr *c;
    
    // the control message payload is not guaranteed to be aligned, so we need
    // to use memcpy to safely write into it
    
    {
        c = CMSG_FIRSTHDR(&msg);
        c->cmsg_len   = CMSG_LEN(sizeof(quint32));
        c->cmsg_level = SOL_ALG;
        c->cmsg_type  = ALG_SET_OP;
        
        Q_ASSERT(dir == QCA::Encode || dir == QCA::Decode);
        const quint32 op = ((dir == QCA::Encode) ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT);
        std::memcpy(CMSG_DATA(c), &op, sizeof(op));
    }
    
    {
        c = CMSG_NXTHDR(&msg, c);
        c->cmsg_len   = CMSG_LEN(sizeof(struct ::af_alg_iv) + iv.size());
        c->cmsg_level = SOL_ALG;
        c->cmsg_type  = ALG_SET_IV;
        
        const quint32 iv_len = iv.size();
        std::memcpy(CMSG_DATA(c) + offsetof(struct ::af_alg_iv, ivlen), &iv_len, sizeof(iv_len));
        std::memcpy(CMSG_DATA(c) + offsetof(struct ::af_alg_iv, iv), iv.data(), iv.size());
    }
    
    if ( ::sendmsg(_alg.op_sock, &msg, MSG_MORE) == -1 ) {
        _alg.deinit();
        _alg.op_sock = -1;
        if (cmsg_data != (void *)(&cmsg_buf)) {
            std::free(cmsg_data);
        }
        
        // warning
        return;
    }
    
    if (cmsg_data != (void *)(&cmsg_buf)) {
        std::free(cmsg_data);
    }
}

bool kcapiCipherContext::update(const QCA::SecureArray &in, QCA::SecureArray *out)
{
    Q_ASSERT(_alg.op_sock > 0 && out);

//     kcapiSpliceHelper splice = { .op_sock = _alg.op_sock, .in = in, .out = nullptr };
//     
//     if ( splice.send(SPLICE_F_MORE) == -1 ) {
//         qWarning("qca-linux encountered an error sending hash input to the kernel: (%d) %s", splice.errno_, std::strerror(splice.errno_));
//         return false;
//     }
    
    QCA::SecureArray a(g_page_size, '\0');
    
    struct ::iovec recv_iov;
    struct ::msghdr recv_msg;
    
    std::memset(&recv_iov, '\0', sizeof(recv_iov));
    recv_iov.iov_base = a.data();
    recv_iov.iov_len = a.size();

    std::memset(&recv_msg, '\0', sizeof(recv_msg));
    recv_msg.msg_iov = &recv_iov;
    recv_msg.msg_iovlen = 1;

    int result_len = 0;
    
    for(;;) {
        
        int recv_len = ::recvmsg(_alg.op_sock, &recv_msg, 0);
        if (recv_len < 0) {
            const int errno_ = errno;
            qWarning("qca-linux encountered an error receiving cipher output from the kernel: %s", ::strerror(errno_));
            
            return false;
        }
        
        result_len += recv_len;
        if (recv_msg.msg_flags & MSG_TRUNC) {
            int oldSize = a.size();
            a.resize(a.size() + (g_page_size - a.size() % g_page_size));
            
            recv_iov.iov_base = a.data() + oldSize;
            recv_iov.iov_len = a.size() - oldSize;
            continue;
        }
        
        break;
    }
    
    a.resize(result_len);
    (*out) = a;
    return true;
}

bool kcapiCipherContext::final(QCA::SecureArray *out)
{
    Q_ASSERT( _alg.op_sock > 0 && out );
    if (out->isEmpty()) {
        (*out) = QCA::SecureArray(g_page_size, '\0');
    }
    
    int offset = 0;
    for (;;) {
        int r = recv(_alg.op_sock, out->data() + offset, out->size() - offset, 0);
        
        Q_ASSERT( r >= 0 );
        if (r + offset < out->size()) {
            out->resize(r + offset);
            return true;
        }
        
        offset += r;
        out->resize(out->size() * 2);
    }
    
    Q_UNREACHABLE();
}

class kcapiProvider final : public QCA::Provider
{
public:
    void init() override
    {
    }

    ~kcapiProvider() override = default;

    int qcaVersion() const override
    {
        return QCA_VERSION;
    }

    QString name() const override
    {
        return QStringLiteral("qca-linux");
    }

    QStringList features() const override
    {
        return g_driverDatabase->names();
    }

    Context *createContext(const QString &type) override
    {
        kcapiDriverInfo driver;

        if (!g_driverDatabase->get(type, driver)) {
            // warning
            return nullptr;
        }

        switch(driver.type)
        {
        case kcapiDriverInfo::Hash:
            return new kcapiHashContext(this, type, driver);

        case kcapiDriverInfo::SymmetricCipher:
            return new kcapiCipherContext(this, type, driver);

        case kcapiDriverInfo::Random:
            return new kcapiRandomContext(this, driver);

        default:
            Q_UNREACHABLE();
        }
    }
};

class QCALinuxPlugin final : public QObject, public QCAPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
    Q_INTERFACES(QCAPlugin)
    
public:
    QCALinuxPlugin()
    {
#if WITH_DRIVER_INTROSPECTION
        QMetaType::registerConverter(&kcapiDriverInfo::toVariantMap);
#endif
    }
    
    ~QCALinuxPlugin() override = default;
    
    QCA::Provider *createProvider() override
    {
        return new kcapiProvider;
    }
    
#if WITH_DRIVER_INTROSPECTION
    Q_INVOKABLE int reload()
    {
        int ret;
        if (!( ret = g_driverDatabase->reload() )) {
            qInfo("qca-linux driver database manually reloaded.");
        }
        return ret;
    }
    
    QList<kcapiDriverInfo> drivers() const
    {
        return g_driverDatabase->drivers();
    }
    Q_PROPERTY(QList<kcapiDriverInfo> drivers READ drivers)
#endif
    
};

#include "qca-linux.moc"
// #endif // Q_OS_LINUX


#include <string.h>
#include <map>
#include <optional>
#include <stdexcept>
#include <functional>
#include <yajl/yajl_tree.h>

template<typename T> T get(yajl_val val);

template<> inline std::string get<std::string>(yajl_val val)
{
    auto str = YAJL_GET_STRING(val);
    if (!str) throw std::runtime_error("Not a string(" + std::to_string(val->type) + ")");
    //else
    return str;
}

template<> inline std::optional<std::string> get<std::optional<std::string>>(yajl_val val)
{
    auto str = YAJL_GET_STRING(val);
    return str? std::make_optional(str) : std::nullopt;
}

template<> inline bool get<bool>(yajl_val val)
{
    if (YAJL_IS_TRUE(val)) return true;
    if (YAJL_IS_FALSE(val)) return false;
    //else
    throw std::runtime_error("Not a boolean");
}

inline bool is_true(yajl_val val)
{
    return (YAJL_IS_TRUE(val))? true : false;
}

template<> inline uint16_t get<uint16_t>(yajl_val val)
{
    if (!YAJL_IS_INTEGER(val)) throw std::runtime_error("Not an integer");
    auto intval = YAJL_GET_INTEGER(val);
    if (intval > std::numeric_limits<uint16_t>::max()) throw std::runtime_error("Number too big for uint16_t");
    return (uint16_t)intval;
}

template<> inline std::optional<uint16_t> get<std::optional<uint16_t>>(yajl_val val)
{
    return (YAJL_IS_INTEGER(val))? std::make_optional(get<uint16_t>(val)) : std::nullopt;
}

template<> inline uint64_t get<uint64_t>(yajl_val val)
{
    if (!YAJL_IS_INTEGER(val)) throw std::runtime_error("Not an integer");
    return YAJL_GET_INTEGER(val);
}

template<> inline std::vector<yajl_val> get<std::vector<yajl_val>>(yajl_val val)
{
    auto arr = YAJL_GET_ARRAY(val);
    if (!arr) throw std::runtime_error("Not a JSON array");
    std::vector<yajl_val> v;
    for (int i = 0; i < arr->len; i++) {
        v.push_back(arr->values[i]);
    }
    return v;
}

template<> inline std::map<std::string,yajl_val> get<std::map<std::string,yajl_val>>(yajl_val val)
{
    auto obj = YAJL_GET_OBJECT(val);
    if (!obj) throw std::runtime_error("Not a JSON object");
    //else
    std::map<std::string,yajl_val> m;
    for (int i = 0; i < obj->len; i++) {
        m[obj->keys[i]] = obj->values[i];
    }
    return m;
}

inline yajl_val get(yajl_val val, const std::vector<yajl_val>::size_type i)
{
    return get<std::vector<yajl_val>>(val).at(i);
}

inline yajl_val get(yajl_val val, const std::string& propname)
{
    return get<std::map<std::string,yajl_val>>(val).at(propname);
}
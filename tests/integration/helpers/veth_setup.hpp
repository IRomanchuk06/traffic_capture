#pragma once
#include <cstdlib>
#include <iostream>
#include <string>

// class to create/destroy virtual ethernet pair
class VethPair {
public:
    VethPair(const std::string& name1, const std::string& name2)
        : veth1(name1), veth2(name2), created(false) {
        create();
    }

    ~VethPair() {
        if (created) {
            destroy();
        }
    }

    bool is_created() const {
        return created;
    }
    const std::string& get_veth1() const {
        return veth1;
    }
    const std::string& get_veth2() const {
        return veth2;
    }

private:
    std::string veth1;
    std::string veth2;
    bool created;

    void create() {
        std::string cmd = "ip link add " + veth1 + " type veth peer name " + veth2;
        int ret = system(cmd.c_str());
        if (ret == 0) {
            ret = system(("ip link set " + veth1 + " up").c_str());
            if (ret != 0) {
                std::cerr << "Failed to bring up interface " << veth1 << std::endl;
            }
            ret = system(("ip link set " + veth2 + " up").c_str());
            if (ret != 0) {
                std::cerr << "Failed to bring up interface " << veth2 << std::endl;
            }
            created = true;
            std::cout << "Created veth pair: " << veth1 << " <-> " << veth2 << std::endl;
        } else {
            std::cerr << "Failed to create veth pair (may need sudo)" << std::endl;
            created = false;
        }
    }

    void destroy() {
        std::string cmd = "ip link del " + veth1;
        int ret = system(cmd.c_str());
        if (ret != 0) {
            std::cerr << "Failed to delete veth pair: " << veth1 << std::endl;
        } else {
            std::cout << "🗑️  Deleted veth pair: " << veth1 << std::endl;
        }
    }
};

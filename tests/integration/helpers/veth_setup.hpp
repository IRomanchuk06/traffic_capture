#pragma once
#include <string>
#include <cstdlib>
#include <iostream>

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

    bool is_created() const { return created; }
    const std::string& get_veth1() const { return veth1; }
    const std::string& get_veth2() const { return veth2; }

private:
    std::string veth1;
    std::string veth2;
    bool created;

    void create() {
        std::string cmd = "ip link add " + veth1 + " type veth peer name " + veth2;
        if (system(cmd.c_str()) == 0) {
            system(("ip link set " + veth1 + " up").c_str());
            system(("ip link set " + veth2 + " up").c_str());
            created = true;
            std::cout << "Created veth pair: " << veth1 << " <-> " << veth2 << std::endl;
        } else {
            std::cerr << "Failed to create veth pair (may need sudo)" << std::endl;
            created = false;
        }
    }

    void destroy() {
        std::string cmd = "ip link del " + veth1;
        system(cmd.c_str());
        std::cout << "🗑️  Deleted veth pair: " << veth1 << std::endl;
    }
};

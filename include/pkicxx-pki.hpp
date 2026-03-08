#include <string>
#include <vector>

extern "C" struct evp_pkey_st;

namespace pkicxx
{
  class pkic
  {
    public:
      pkic();
      
      // PKIC pair generators
      void generate_keypair(int length);
            
      // DER loaders
      void loadPrivDER(std::vector<unsigned char> DER);
      void loadPubDER(std::vector<unsigned char> DER);

      // DER getters
      std::vector<unsigned char> getPrivDER();
      std::vector<unsigned char> getPubDER();
      
      // PEM loaders
      void importPEM(std::string file);
      void loadPEMStr(std::string PEM);

      // PEM exporters
      void exportPrivPEM(std::string file);
      void exportPubPEM(std::string file);
      void exportBundlePEM(std::string file);

      // PEM string getters
      std::string getPubPEM();
      std::string getPrivPEM();
      std::string getBundlePEM();

      private:
        ::evp_pkey_st *key_container = nullptr;
  };
} 

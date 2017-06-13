#ifndef QEMUCONFIGURATION_H
#define QEMUCONFIGURATION_H

#include <iostream>
#include <stdint.h>
#include <vector>
#include <set>

class QemuConfiguration
{
public:
    QemuConfiguration();

    bool saveConfiguration(std::string pathname);
    bool loadConfiguration(std::string pathname);

    void setDriveA(std::string filename, bool qcow2Format);
    std::string getDriveA() const;
    bool getDriveAQCow2() const;

    void setDriveB(std::string filename, bool qcow2Format);
    std::string getDriveB() const;
    bool getDriveBQCow2() const;

    void setOpticalDrive(std::string filename);
    std::string getOpticalDrive() const;

    void setProcessorType(std::string processorName);
    static std::set<std::string> getQemuProcessorTypeList();
    std::string getProcessorType() const;

    void setNetworkAdapterType(std::string networkAdapterName);
    static std::set<std::string> getQemuNetworkAdapterTypeList();
    std::string getNetworkAdapterType() const;

    /**
     * Allows someone to configure the human interface on, the port number will be calculated as
     * +1 of the QMP port number
     */
    void enableHumanInterfaceSocket(bool enable);
    bool humanInterfaceSocketEnabled() const;

    void setOtherOptions(std::string otherOptions);
    std::string getOtherOptions() const;

    void setMemorySize(uint16_t numMegabytes);
    static std::set<std::string> getMemorySizes();
    uint16_t getMemorySize() const;

    void setVgaType(std::string vgaType);
    static std::set<std::string> getVgaTypes();
    std::string getVgaType() const;

    int getNumberOfPortsPerInstance() const;

    void setStartingPortNumber(uint16_t portNumber);
    uint16_t getStartingPortNumber() const;

    void setNumberOfCpus(uint8_t numCpus);
    uint8_t getNumberOfCpus() const;

    bool getCommandLine(std::string & commandName, std::vector<std::string> & args) const;

protected:

    bool buildCpuArgs(std::string & commandName, std::vector<std::string> & args) const;

    bool buildDriveArgs(std::vector<std::string> & args) const;

    bool buildNetworkArgs(std::vector<std::string> & args) const;

    bool buildQmpArgs(std::vector<std::string> & args) const;

    bool buildMonitorSocketArgs(std::vector<std::string> & args) const;

    bool buildOtherArgs(std::vector<std::string> & args) const;

    bool buildMemoryArgs(std::vector<std::string> & args) const;

    std::string theDriveA;
    bool    theDriveAQcow2;

    std::string theDriveB;
    bool    theDriveBQcow2;

    std::string theOpticalDrive;

    static const std::set<std::string> theDefaultCpuTypes;
    std::string theCpuType;
    uint8_t theNumberCpus;

    static const std::set<std::string> theDefaultNetworkAdapters;
    std::string theNetworkAdapter;

    bool theHumanInterfaceEnabled;

    std::string theOtherOptions;

    uint16_t theMemoryMb;

    static const std::set<std::string> theDefaultVgaTypes;
    std::string theVideoAdapter;


    uint16_t theStartingPortNumber;
};

#endif // QEMUCONFIGURATION_H

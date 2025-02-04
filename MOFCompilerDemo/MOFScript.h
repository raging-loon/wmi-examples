#pragma once

#include <string>

const std::string MOF_SCRIPT = R"mof(

#PRAGMA NAMESPACE("\\\\.\\root\\subscription")

instance of __EventFilter as $Filter{

	Name = "Innocuous Application";
	EventNamespace = "ROOT\\CIMV2";
	Query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 "
			"WHERE TargetInstance ISA 'Win32_LogonSession'";
	QueryLangauge = "WQL";

};

instance of CommandLineEventConsumer as $Consumer{
	Name = "Innocuous Event Consumer";
	RunInteractively = false;
	CommandLineTemplate = "cmd.exe / c echo \"hello\" > C:\\hello.txt";
};

instance of __FilterToConsumerBinding{
	Filter = $Filter;
	Consumer = $Consumer;
};)mof";

import {useState, useEffect} from 'react';
import './App.css';
import { GetDefaulOutboundIP } from '../wailsjs/go/main/App';
import { GetIPInfo } from '../wailsjs/go/main/App';
import { GetAllIPv4Interfaces } from '../wailsjs/go/main/App';
import { FaEthernet, FaRightLeft, FaNetworkWired } from "react-icons/fa6";
import { RiGlobalLine } from "react-icons/ri";
import { SiSpeedtest } from "react-icons/si";
import Select from './components/Select';

function App() {
    const [defaultOutboundIP, setDefaultOutboundIP] = useState('0.0.0.0');
    const [sourceIP, setSourceIP] = useState('0.0.0.0');
    const [ipv4List, setIPv4List] = useState([]);
    const [resultNAT, setResultNAT] = useState('Unknown');
    const [resultIP, setResultIP] = useState('Unknown');
    const [onTest, setOnTest] = useState(false);

    useEffect(() => {
        GetDefaulOutboundIP().then(
            (ip) => {
                setDefaultOutboundIP(ip);
                setSourceIP(ip);
            }
        );
    }, []);

    useEffect(() => {
        GetAllIPv4Interfaces().then(setIPv4List);
    }, []);

    useEffect(() => {
        const interval = setInterval(() => {
            GetDefaulOutboundIP().then(
                (ip) => {
                    setDefaultOutboundIP(ip);
                    GetAllIPv4Interfaces().then(
                        (list) => {
                            if (!list.includes(sourceIP)) {
                                setSourceIP(ip);
                            }
                            setIPv4List(list);
                        }
                    );
                }
            );
        }, 5000);
    
        return () => clearInterval(interval);
    }, [sourceIP])

    const test = () => {
        setOnTest(true);
        GetIPInfo(sourceIP).then((result) => {
            result = result.split('|');
            setResultNAT(result[0]);
            setResultIP(result[1]);
            setOnTest(false);
        }
        );
    }

    return (
        <div className="bg-gray-900 flex flex-col h-screen text-white">
            <div className="flex flex-row mx-5 text-2xl font-bold mt-10 gap-2">
                NAT Type Detection
                <div className={onTest ? 'rotate-icon' : ''}>
                    🤡
                </div>
            </div>
            <div className="flex">
                <div className='border-2 border-white m-5 p-3 rounded-lg'>
                    <div className='text-cyan-500 font-bold text-xs'>
                        <FaEthernet />
                        Lan IP
                    </div>
                    <div className='flex font-bold text-2xl'>
                        {sourceIP}
                    </div>
                </div>
                <div className='border-2 border-white m-5 p-3 rounded-lg'>
                    <div className='text-cyan-500 font-bold text-xs'>
                        <FaRightLeft />
                        NAT Type
                    </div>
                    <div className='flex font-bold text-2xl'>
                        {resultNAT}
                    </div>
                </div>
                <div className='border-2 border-white m-5 p-3 rounded-lg'>
                    <div className='text-cyan-500 font-bold text-xs'>
                        <RiGlobalLine />External IP
                    </div>
                    <div className='flex font-bold text-2xl'>
                        {resultIP}
                    </div>
                </div>
            </div>
            <div className='flex'>
                <button
                    onClick={test}
                    disabled={onTest}
                    className='bg-cyan-500 hover:bg-cyan-700 text-white font-bold py-2 px-4 rounded-2xl mx-5 flex gap-2'
                >
                    <SiSpeedtest size={22} />
                    {onTest ? 'Testing NAT...' : 'Test NAT Type'}
                </button>
            </div>
            <div className='m-5'>
                <div className='tag'>
                    Option settings:
                </div>
                <div className='flex flex-row gap-2'>
                    <div className='text-cyan-500 font-bold text-base flex gap-1 h-10 pt-4'>
                        Outbound IP <FaNetworkWired style={{marginTop: '0.3rem'}} />
                    </div>
                    <div className='w-40 h-10'>
                        <Select selected={sourceIP ? sourceIP : defaultOutboundIP} setSelected={setSourceIP} items={ipv4List} />
                    </div>
                </div>
            </div>
        </div>
    )
}

export default App

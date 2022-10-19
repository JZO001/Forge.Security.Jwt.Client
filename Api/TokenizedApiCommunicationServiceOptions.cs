using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Text;

namespace Forge.Security.Jwt.Client.Api
{

    /// <summary>Represents the default values for a Http request</summary>
    public class TokenizedApiCommunicationServiceOptions
    {

        /// <summary>Initializes a new instance of the <see cref="TokenizedApiCommunicationServiceOptions" /> class.</summary>
        public TokenizedApiCommunicationServiceOptions()
        {
            Request_Header_Accepts.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        /// <summary>Configure the header accept list for a request</summary>
        /// <value>List of media types</value>
        public List<MediaTypeWithQualityHeaderValue> Request_Header_Accepts { get; private set; } = new List<MediaTypeWithQualityHeaderValue>();

        /// <summary>Gets or sets the request encoding.
        /// Default is UTF8.</summary>
        /// <value>The request encoding.</value>
        public Encoding RequestEncoding { get; set; } = Encoding.UTF8;

        /// <summary>Gets or sets the type of the request media type.
        /// Default is "application/json".</summary>
        /// <value>The type of the request media.</value>
        public string RequestMediaType { get; set; } = "application/json";

    }

}

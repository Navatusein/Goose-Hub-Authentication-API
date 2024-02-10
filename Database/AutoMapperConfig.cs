using AutoMapper;

namespace AuthenticationAPI.Database
{
    /// <summary>
    /// Configuration of AutoMapper
    /// </summary>
    public class AutoMapperConfig : Profile
    {
        /// <summary>
        /// Constructor of class AutoMapperConfig
        /// </summary>
        public AutoMapperConfig()
        {
            //CreateMap<ClassFrom, ClassTo>().ReverseMap();
        }
    }
}

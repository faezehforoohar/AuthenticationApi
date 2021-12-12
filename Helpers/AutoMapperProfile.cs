using AutoMapper;
using AuthenticationApi.Entities;
using AuthenticationApi.Models.Users;

namespace AuthenticationApi.Helpers
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            CreateMap<User, UserModel>();
        }
    }
}
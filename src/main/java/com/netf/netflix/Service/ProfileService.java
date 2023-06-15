package com.netf.netflix.Service;

import com.netf.netflix.Entity.Member;
import com.netf.netflix.Entity.Profile;
import com.netf.netflix.Entity.ProfileImg;
import com.netf.netflix.Entity.Video;
import com.netf.netflix.Repository.ProfileRepository;
import com.netf.netflix.Repository.VideoRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.*;

@Service
@RequiredArgsConstructor
public class ProfileService {
    private final ProfileRepository profileRepository;
    private final VideoRepository videoRepository;
    private final ProfileImgService profileImgService;

    public void saveProfile(Profile profile) {
        profileRepository.save(profile);
    }

    public void updateProfile(Profile profile, String name, String language, String nickname, String maturityLevel) {
        profile.setName(name);
        profile.setLanguage(language);
        profile.setNickname(nickname);
        profile.setMaturityLevel(maturityLevel);
        profileRepository.save(profile);
    }

    public void addVideoToFavorites(Long profileId, Long videoId) {
        Profile profile = profileRepository.findById(profileId)
                .orElseThrow(() -> new RuntimeException("Profile not found"));

        if (profile.getFavoriteVideos() == null) {
            profile.setFavoriteVideos(new HashSet<>());
            System.out.println("Favorite videos set created");
        } else if (profile.getFavoriteVideos().contains(videoId)) {
            profile.getFavoriteVideos().remove(videoId);
            profileRepository.save(profile);
            System.out.println("Video already added to favorites, removed it from the list");
            throw new RuntimeException("Video already added to favorites");
        }

        profile.getFavoriteVideos().add(videoId);
        profileRepository.save(profile);
        printFavoriteVideoIds(profileId);
    }

    public void printFavoriteVideoIds(long profileId) {
        System.out.println(profileId + "의 좋아요 목록");
        Optional<Profile> profile = profileRepository.findById(profileId);
        if (profile.isPresent()) {
            Set<Long> favoriteVideos = profile.get().getFavoriteVideos();
            System.out.println(profileId + "'s playList");
            for (Long videoId : favoriteVideos) {
                System.out.println("Favorite Video ID: " + videoId);
            }
        }
    }

    public void addRecentlyViewedVideo(Long profileId, Long videoId) {
        Profile profile = profileRepository.findById(profileId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid profile ID"));
        List<Long> recentlyViewedVideos = profile.getRecentlyViewedVideos();

        if (recentlyViewedVideos == null) {
            recentlyViewedVideos = new ArrayList<>();
        }

        recentlyViewedVideos.remove(videoId);
        recentlyViewedVideos.add(0, videoId);

        if (recentlyViewedVideos.size() > 10) {
            recentlyViewedVideos = recentlyViewedVideos.subList(0, 10);
        }

        profile.setRecentlyViewedVideos(recentlyViewedVideos);
        profileRepository.save(profile);
        printRecentlyViewedVideos(profileId);
    }

    public void printRecentlyViewedVideos(Long profileId) {
        Profile profile = profileRepository.findById(profileId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid profile ID"));
        List<Long> recentlyViewedVideos = profile.getRecentlyViewedVideos();

        if (recentlyViewedVideos != null) {
            System.out.println(profileId + "'s Recently viewed");
            for (Long videoId : recentlyViewedVideos) {
                System.out.println("Recently viewed video ID: " + videoId);
            }
        }
    }

    public Profile getProfileById(Long profileId) {
        return profileRepository.findById(profileId).orElse(null);
    }

    public void ProfileImgsave(MultipartFile ProfileImgFile) throws Exception {
        ProfileImg profileImg = new ProfileImg();
        profileImgService.uploadProfileImg(profileImg, ProfileImgFile);
    }

    public List<Profile> getAllProfiles() {
        return profileRepository.findAll();
    }

    public void updateProfileImage(Long profileId, String imageUrl) {
        Profile profile = profileRepository.findById(profileId)
                .orElseThrow(() -> new RuntimeException("Profile not found"));

        profile.setImageUrl(imageUrl);
        profileRepository.save(profile);
    }

    public void deleteProfileImage(Long profileId) {
        Profile profile = profileRepository.findById(profileId)
                .orElseThrow(() -> new RuntimeException("Profile not found"));

        profile.setImageUrl(null);
        profileRepository.save(profile);
    }
}
